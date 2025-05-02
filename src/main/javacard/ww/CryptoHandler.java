package main.javacard.ww;

import javacard.framework.*;
import javacard.security.MessageDigest;
import javacard.security.KeyPair;
import javacard.security.ECPublicKey;
import javacard.security.Signature;
import javacard.security.ECPrivateKey;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

/**
 * Handles the core cryptographic operations and state management as a separate Applet.
 * Implements the SharedCryptoInterface for inter-applet communication.
 */
public class CryptoHandler extends Applet implements SharedCryptoInterface {

    /** Applet Instance AID: A000000647 43485F414944 ("CH_AID") */
    public static final byte[] AID_BYTES = {
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x47,
        (byte)0x43, (byte)0x48, (byte)0x5F, (byte)0x41, (byte)0x49, (byte)0x44
    };

    // Configuration and State Constants
    private static final byte MAX_PASSWORD_TRIES = 10;
    private static final short DERIVED_KEY_LENGTH = 16; // Length of the key derived from user password
    private static final short AUTH_HASH_LENGTH = 32;   // SHA-256 hash length for authentication

    // Configuration Version Bytes (returned by CMD_GET_CONFIG)
    private static final byte CONFIG_VERSION_MAJOR = (byte) 0x01;
    private static final byte CONFIG_VERSION_MINOR = (byte) 0x00;
    private static final byte CONFIG_VERSION_PATCH = (byte) 0x00;
    private static final byte CONFIG_EDITION_STANDARD = (byte) 0x01; // Standard edition identifier

    // Configuration Flags (bitmask)
    private static final byte FLAG_INITIALIZED = (byte) 0x01; // Set after initial key generation
    private static final byte FLAG_KEY_EXPORTED = (byte) 0x02; // Set after key export (currently unused)

    // Authentication Constants (used in verifyAuthHashInternal)
    private static final byte[] AUTH_PREFIX = {(byte)0x19}; // Prefix for hashing
    private static final byte[] AUTH_STRING = {'P','a','s','s','w','o','r','d',' ',
                                             'a','u','t','h','e','n','t','i','c',
                                             'a','t','i','o','n',':','\n'};

    // Cryptographic Constants
    private static final short KEY_SIZE = 256; // SECP256k1 key size in bits
    private static final short UNCOMPRESSED_PKEY_LENGTH = 65; // Public key length (0x04 + X + Y)
    private static final short PRIVATE_KEY_LENGTH = 32; // Private key length
    private static final short COUNTER_LENGTH = 4; // U2F signature counter length

    // Command Bytes (used in processCryptoCommand)
    private static final byte CMD_SIGN = (byte) 0x01;         // Sign data
    private static final byte CMD_GET_PKEY = (byte) 0x02;     // Get public key
    private static final byte CMD_GEN_KEY = (byte) 0x03;      // Generate initial key pair / set password
    private static final byte CMD_GET_CONFIG = (byte) 0x04;   // Get configuration info
    private static final byte CMD_SET_STATUS = (byte) 0x05;   // Set status byte (requires auth)
    private static final byte CMD_EXPORT_KEY = (byte) 0x06;   // Export encrypted private key (requires auth)
    private static final byte CMD_SET_PASSWORD = (byte) 0x07; // Change password (requires auth with old password)
    private static final byte CMD_RESET = (byte) 0x08;        // Reset card state (requires auth)

    // Command Data Offsets and Lengths (for parsing commandDataBuffer in processCryptoCommand)
    // CMD_SIGN: [AuthHash(32)] [DataHashToSign(32)]
    private static final short OFFSET_SIGN_AUTH_HASH = 0;
    private static final short OFFSET_SIGN_DATA_HASH = AUTH_HASH_LENGTH; // 32
    private static final short SIGN_DATA_HASH_LENGTH = 32;
    private static final short SIGN_CMD_DATA_LENGTH = OFFSET_SIGN_DATA_HASH + SIGN_DATA_HASH_LENGTH; // 64

    // CMD_GEN_KEY: [DerivedKey(16)]
    private static final short OFFSET_GEN_KEY_DERIVED_KEY = 0;
    private static final short GEN_KEY_DERIVED_KEY_LENGTH = DERIVED_KEY_LENGTH; // 16
    private static final short GEN_KEY_CMD_DATA_LENGTH = GEN_KEY_DERIVED_KEY_LENGTH;

    // CMD_SET_STATUS: [AuthHash(32)] [StatusByte(1)]
    private static final short OFFSET_SET_STATUS_AUTH_HASH = 0;
    private static final short OFFSET_SET_STATUS_DATA = AUTH_HASH_LENGTH; // 32
    private static final short SET_STATUS_DATA_LENGTH = 1;
    private static final short SET_STATUS_CMD_DATA_LENGTH = OFFSET_SET_STATUS_DATA + SET_STATUS_DATA_LENGTH; // 33

    // CMD_EXPORT_KEY: [AuthHash(32)] [DummyData(1)] (Dummy data is authenticated but ignored)
    private static final short OFFSET_EXPORT_KEY_AUTH_HASH = 0;
    private static final short OFFSET_EXPORT_KEY_DUMMY_DATA = AUTH_HASH_LENGTH; // 32
    private static final short EXPORT_KEY_DUMMY_DATA_LENGTH = 1;
    private static final short EXPORT_KEY_CMD_DATA_LENGTH = OFFSET_EXPORT_KEY_DUMMY_DATA + EXPORT_KEY_DUMMY_DATA_LENGTH; // 33

    // CMD_SET_PASSWORD: [AuthHash(32)] [NewDerivedKey(16)]
    private static final short OFFSET_SET_PASSWORD_AUTH_HASH = 0;
    private static final short OFFSET_SET_PASSWORD_NEW_KEY = AUTH_HASH_LENGTH; // 32
    private static final short SET_PASSWORD_NEW_KEY_LENGTH = DERIVED_KEY_LENGTH; // 16
    private static final short SET_PASSWORD_CMD_DATA_LENGTH = OFFSET_SET_PASSWORD_NEW_KEY + SET_PASSWORD_NEW_KEY_LENGTH; // 48

    // CMD_RESET: [AuthHash(32)] [DummyData(1)] (Dummy data is authenticated but ignored)
    private static final short OFFSET_RESET_AUTH_HASH = 0;
    private static final short OFFSET_RESET_DUMMY_DATA = AUTH_HASH_LENGTH; // 32
    private static final short RESET_DUMMY_DATA_LENGTH = 1;
    private static final short RESET_CMD_DATA_LENGTH = OFFSET_RESET_DUMMY_DATA + RESET_DUMMY_DATA_LENGTH; // 33

    // AES Constants (for CMD_EXPORT_KEY)
    private static final byte IV_LENGTH = 16; // AES CBC IV length

    // Instance variables for AES Encryption/Decryption (used for key export)
    private AESKey aesKey;
    private Cipher aesCipher;
    private byte[] iv; // Initialization Vector (transient)
    private RandomData randomData; // For generating random IV

    // Instance variables for Core State and ECC Operations
    private byte[] counter; // U2F signature counter (persistent)
    private KeyPair keyPair; // SECP256k1 key pair
    private ECPublicKey pubKey; // Public key part
    private ECPrivateKey privKey; // Private key part
    private Signature signature; // ECDSA signature object
    private byte[] storedDerivedKey; // Derived key from password (persistent)
    private byte passwordTries; // Failed password attempt counter (persistent)
    private boolean isLocked; // Lock state if password tries exceeded (persistent)
    private MessageDigest sha256; // SHA-256 digest object
    private byte configEdition; // Configuration edition (persistent)
    private byte configFlags; // Configuration flags (persistent)
    private byte configStatus; // User-settable status byte (persistent)

    /** Private constructor called by install(). Initializes crypto objects and state. */
    private CryptoHandler() {
        // Initialize persistent state
        counter = new byte[COUNTER_LENGTH];
        counter[3] = 1; // Initialize counter to 1
        configEdition = CONFIG_EDITION_STANDARD;
        configFlags = 0; // Not initialized initially
        configStatus = 0;
        generateNewKeyPairInternal();
        signature = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        storedDerivedKey = new byte[DERIVED_KEY_LENGTH];
        passwordTries = 0;
        isLocked = false;

        // Initialize AES components (used for key export)
        aesKey = (AESKey)KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        iv = JCSystem.makeTransientByteArray(IV_LENGTH, JCSystem.CLEAR_ON_DESELECT); // Transient IV buffer
        randomData = RandomData.getInstance(RandomData.ALG_TRNG); // True Random Number Generator
    }

    /** Called by the JCRE to install this applet. */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Create an instance of the Applet
        new CryptoHandler().register(AID_BYTES, (short)0, (byte)AID_BYTES.length);
    }

    /** Returns this object as the Shareable Interface Object. */
    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
         return this;
    }

    /** Processes APDUs sent directly to this applet (currently unsupported). */
    @Override
    public void process(APDU apdu) throws ISOException {
        // This applet is primarily accessed via SIO. 
        // We could potentially add APDU commands here for direct management if needed,
        // but for now, we just prevent applet selection after installation.
        if (selectingApplet()) {
            return; // Allow selection, but no commands afterwards
        }

        // Throw error if any command is sent directly after selection
        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
    }

    // --- Implementation of SharedCryptoInterface ---

    /**
     * Processes a cryptographic command received via SIO.
     * Dispatches to internal handlers based on the command byte.
     * Handles command length validation. Authentication is handled within specific command handlers.
     *
     * @param commandDataBuffer Buffer containing the command byte and its associated data.
     * @param commandDataOffset Offset of the command byte within commandDataBuffer.
     * @param commandDataLength Total length of the command byte plus its data.
     * @param outputBuffer Buffer to store the raw result of the command.
     * @param outputOffset Starting offset in the output buffer.
     * @return The total length of the raw data written to the output buffer.
     * @throws ISOException if command is invalid, length is wrong, or internal operation fails.
     */
    @Override
    public short processCryptoCommand(byte[] commandDataBuffer, short commandDataOffset, short commandDataLength,
                                      byte[] outputBuffer, short outputOffset) {
        try {
            if (commandDataLength < 1) {
                ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
            }

            byte cmd = commandDataBuffer[commandDataOffset];
            short actualDataOffset = (short)(commandDataOffset + 1);
            short actualDataLength = (short)(commandDataLength - 1);

            switch (cmd) {
                case CMD_SIGN:
                    if (actualDataLength < SIGN_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return signDataInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SIGN_AUTH_HASH),
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SIGN_DATA_HASH),
                        outputBuffer, outputOffset
                    );

                case CMD_GET_PKEY:
                    if (actualDataLength != 0) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return getPkeyInternal(outputBuffer, outputOffset);

                case CMD_GEN_KEY:
                    if (actualDataLength < GEN_KEY_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return genKeyInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_GEN_KEY_DERIVED_KEY),
                        GEN_KEY_DERIVED_KEY_LENGTH,
                        outputBuffer, outputOffset
                    );

                case CMD_GET_CONFIG:
                    if (actualDataLength != 0) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return getConfig(outputBuffer, outputOffset);

                case CMD_SET_STATUS:
                    if (actualDataLength < SET_STATUS_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return setStatusInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SET_STATUS_AUTH_HASH),
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SET_STATUS_DATA),
                        outputBuffer, outputOffset
                    );

                case CMD_EXPORT_KEY:
                    if (actualDataLength < EXPORT_KEY_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return exportKeyInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_EXPORT_KEY_AUTH_HASH),
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_EXPORT_KEY_DUMMY_DATA),
                        EXPORT_KEY_DUMMY_DATA_LENGTH, 
                        outputBuffer, outputOffset
                    );

                case CMD_SET_PASSWORD:
                    if (actualDataLength < SET_PASSWORD_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return setPasswordInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SET_PASSWORD_AUTH_HASH),
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_SET_PASSWORD_NEW_KEY),
                        SET_PASSWORD_NEW_KEY_LENGTH,
                        outputBuffer, outputOffset
                    );

                case CMD_RESET:
                    if (actualDataLength < RESET_CMD_DATA_LENGTH) {
                        ISOException.throwIt(CryptoErrors.ERR_INVALID_LENGTH);
                    }
                    return resetCardInternal(
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_RESET_AUTH_HASH),
                        commandDataBuffer, (short)(actualDataOffset + OFFSET_RESET_DUMMY_DATA),
                        RESET_DUMMY_DATA_LENGTH,
                        outputBuffer, outputOffset
                    );

                default:
                    ISOException.throwIt(CryptoErrors.ERR_INVALID_COMMAND);
            }
        } catch (ISOException e) {
            // Check if this is one of our custom errors
            short reason = e.getReason();
            if (CryptoErrors.isError(reason)) {
                // If it's our custom error, pass it through
                return CryptoErrors.writeError(outputBuffer, outputOffset, reason);
            }
            // If it's not our error, map it to an unknown error
            return CryptoErrors.writeError(outputBuffer, outputOffset, CryptoErrors.ERR_CRYPTO_FAILED);
        } catch (Exception e) {
            // Any other unexpected error
            return CryptoErrors.writeError(outputBuffer, outputOffset, CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Retrieves the current 4-byte counter value.
     * Called by U2fApplet via SIO to prepend to the signature response.
     *
     * @param buffer The buffer to copy the counter value into.
     * @param offset The starting offset in the buffer.
     * @return The length of the counter copied (always COUNTER_LENGTH).
     */
    @Override
    public short getLastCounterValue(byte[] buffer, short offset) {
        // No checks needed, just copy the counter value
        Util.arrayCopyNonAtomic(counter, (short)0, buffer, offset, COUNTER_LENGTH);
        return COUNTER_LENGTH;
    }

    // --- Internal Command Handlers ---

    /**
     * Internal handler for CMD_SIGN.
     * Verifies authentication hash, increments counter, signs the data hash.
     *
     * @param authHashBuffer Buffer containing the authentication hash.
     * @param authHashOffset Offset of the authentication hash.
     * @param dataToSignBuffer Buffer containing the 32-byte hash to be signed.
     * @param dataToSignOffset Offset of the hash to be signed.
     * @param outputBuffer Buffer to store the resulting signature.
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the signature written.
     * @throws ISOException If locked, authentication fails, or signing error occurs.
     */
    private short signDataInternal(byte[] authHashBuffer, short authHashOffset,
                                   byte[] dataToSignBuffer, short dataToSignOffset,
                                   byte[] outputBuffer, short outputOffset) throws ISOException {
        // Verify authentication hash against the derived key and the data being signed
        if (!verifyAuthHashInternal(authHashBuffer, authHashOffset, dataToSignBuffer, dataToSignOffset, SIGN_DATA_HASH_LENGTH)) {
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED);
        }
        incrementCounterInternal(); // Increment counter *after* successful authentication
        
        try {
            signature.init(privKey, Signature.MODE_SIGN);
            // Sign the pre-computed hash provided in dataToSignBuffer
            short sigLen = signature.signPreComputedHash(dataToSignBuffer, dataToSignOffset, SIGN_DATA_HASH_LENGTH, outputBuffer, outputOffset);
            return sigLen;
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Internal handler for CMD_GET_PKEY.
     * Returns the uncompressed public key. Requires the card to be initialized.
     *
     * @param outputBuffer Buffer to store the public key.
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the public key written (UNCOMPRESSED_PKEY_LENGTH).
     * @throws ISOException If the card is not initialized.
     */
    private short getPkeyInternal(byte[] outputBuffer, short outputOffset) throws ISOException {
        // No authentication required for public key, but card must be initialized
        if ((configFlags & FLAG_INITIALIZED) != FLAG_INITIALIZED) {
            ISOException.throwIt(CryptoErrors.ERR_NOT_INITIALIZED);
        }
        try {
            pubKey.getW(outputBuffer, outputOffset); // Get uncompressed public key (W)
            return UNCOMPRESSED_PKEY_LENGTH;
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Internal handler for CMD_GEN_KEY.
     * Generates the initial key pair and sets the initial derived key (password).
     * Can only be called once when the card is not initialized.
     *
     * @param derivedKeyBuffer Buffer containing the initial 16-byte derived key.
     * @param derivedKeyOffset Offset of the derived key.
     * @param derivedKeyLength Length of the derived key (must be DERIVED_KEY_LENGTH).
     * @param outputBuffer Buffer to store the generated public key.
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the public key written (UNCOMPRESSED_PKEY_LENGTH).
     * @throws ISOException If already initialized or derivedKeyLength is incorrect.
     */
    private short genKeyInternal(byte[] derivedKeyBuffer, short derivedKeyOffset, short derivedKeyLength,
                                 byte[] outputBuffer, short outputOffset) throws ISOException {
        // Prevent overwriting existing key/password if already initialized
        if ((configFlags & FLAG_INITIALIZED) == FLAG_INITIALIZED) {
            ISOException.throwIt(CryptoErrors.ERR_ALREADY_INITIALIZED);
        }
        
        try {
            // Store the initial derived key
            Util.arrayCopyNonAtomic(derivedKeyBuffer, derivedKeyOffset, storedDerivedKey, (short)0, DERIVED_KEY_LENGTH);
            generateNewKeyPairInternal(); // Generate new keys
            
            // Reset state on new key generation
            configFlags = FLAG_INITIALIZED; // Set initialized flag, clear others
            configStatus = 0;
            passwordTries = 0;
            isLocked = false;
            counter[0] = 0; counter[1] = 0; counter[2] = 0; counter[3] = 1; // Reset counter

            // Return the newly generated public key
            pubKey.getW(outputBuffer, outputOffset);
            return UNCOMPRESSED_PKEY_LENGTH;
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Retrieves the complete configuration data (version, flags, status, public key).
     * Implements the method from SharedCryptoInterface.
     *
     * @param outputBuffer Buffer to store the configuration bytes.
     * @param outputOffset Starting offset in the output buffer.
     * @return The length of the configuration data written.
     * @throws ISOException if an error occurs (e.g., not initialized).
     */
    @Override
    public short getConfig(byte[] outputBuffer, short outputOffset) throws ISOException {
        // No authentication required for config
        short currentOffset = outputOffset;
        outputBuffer[currentOffset++] = CONFIG_VERSION_MAJOR;
        outputBuffer[currentOffset++] = CONFIG_VERSION_MINOR;
        outputBuffer[currentOffset++] = CONFIG_VERSION_PATCH;
        outputBuffer[currentOffset++] = configEdition;
        outputBuffer[currentOffset++] = configFlags;
        outputBuffer[currentOffset++] = configStatus;
        if ((configFlags & FLAG_INITIALIZED) == FLAG_INITIALIZED) {
            pubKey.getW(outputBuffer, currentOffset);
            currentOffset += UNCOMPRESSED_PKEY_LENGTH;
        }
        return (short)(currentOffset - outputOffset); 
    }

    /**
     * Internal handler for CMD_SET_STATUS.
     * Sets the user-defined status byte after verifying authentication.
     *
     * @param authHashBuffer Buffer containing the authentication hash.
     * @param authHashOffset Offset of the authentication hash.
     * @param statusBuffer Buffer containing the new status byte.
     * @param statusOffset Offset of the new status byte.
     * @param outputBuffer Buffer to store the result (the new status byte).
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the data written (always 1).
     * @throws ISOException If not initialized, locked, or authentication fails.
     */
    private short setStatusInternal(byte[] authHashBuffer, short authHashOffset,
                                  byte[] statusBuffer, short statusOffset,
                                  byte[] outputBuffer, short outputOffset) throws ISOException {
        // Verify authentication hash (status byte is the data being authenticated)
        if (!verifyAuthHashInternal(authHashBuffer, authHashOffset, statusBuffer, statusOffset, SET_STATUS_DATA_LENGTH)) {
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED); // Auth failed
        }
        // Authentication successful, set the status
        configStatus = statusBuffer[statusOffset];
        outputBuffer[outputOffset] = configStatus; // Return the new status
        return (short)1; // Return length 1
    }

    /**
     * Internal handler for CMD_EXPORT_KEY.
     * Exports the private key, encrypted with the derived key using AES-CBC.
     * Requires authentication.
     *
     * @param authHashBuffer Buffer containing the authentication hash.
     * @param authHashOffset Offset of the authentication hash.
     * @param dummyDataBuffer Buffer containing dummy data (used for authentication).
     * @param dummyDataOffset Offset of the dummy data.
     * @param dummyDataLength Length of the dummy data (must be EXPORT_KEY_DUMMY_DATA_LENGTH).
     * @param outputBuffer Buffer to store the result (IV + encrypted private key).
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the data written (IV_LENGTH + length of encrypted key).
     * @throws ISOException If not initialized, locked, authentication fails, or encryption error.
     */
    private short exportKeyInternal(byte[] authHashBuffer, short authHashOffset,
                                  byte[] dummyDataBuffer, short dummyDataOffset, short dummyDataLength,
                                  byte[] outputBuffer, short outputOffset) throws ISOException {
        // Verify authentication hash (using dummy data)
        if (!verifyAuthHashInternal(authHashBuffer, authHashOffset, dummyDataBuffer, dummyDataOffset, dummyDataLength)) {
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED);
        }

        try {
            // Generate random IV for AES-CBC
            randomData.nextBytes(iv, (short)0, IV_LENGTH);

            // Set up AES key and cipher for encryption
            aesKey.setKey(storedDerivedKey, (short)0);
            aesCipher.init(aesKey, Cipher.MODE_ENCRYPT, iv, (short)0, IV_LENGTH);

            // Get private key bytes into a transient buffer
            byte[] tempBuffer = JCSystem.makeTransientByteArray(PRIVATE_KEY_LENGTH, JCSystem.CLEAR_ON_DESELECT);
            privKey.getS(tempBuffer, (short)0); // Get private key scalar (S)

            // Copy the random IV to the beginning of the output buffer
            Util.arrayCopyNonAtomic(iv, (short)0, outputBuffer, outputOffset, IV_LENGTH);

            // Encrypt the raw private key (tempBuffer) and append it after the IV.
            // PKCS5 padding is handled automatically by the cipher instance.
            short encryptedLength = aesCipher.doFinal(tempBuffer, (short)0, PRIVATE_KEY_LENGTH,
                                                      outputBuffer, (short)(outputOffset + IV_LENGTH));

            // Clear the temporary buffer holding the private key
            Util.arrayFillNonAtomic(tempBuffer, (short)0, PRIVATE_KEY_LENGTH, (byte)0);

            // Set the flag indicating the key has been exported
            configFlags |= FLAG_KEY_EXPORTED;

            // Return total length: IV + encrypted data
            return (short)(IV_LENGTH + encryptedLength);
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_EXPORT_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Internal handler for CMD_SET_PASSWORD.
     * Changes the stored derived key after authenticating with the old key.
     * Resets the lock state.
     *
     * @param authHashBuffer Buffer containing the authentication hash (calculated with OLD derived key).
     * @param authHashOffset Offset of the authentication hash.
     * @param newDerivedKeyBuffer Buffer containing the NEW 16-byte derived key.
     * @param newDerivedKeyOffset Offset of the new derived key.
     * @param newDerivedKeyLength Length of the new derived key.
     * @param outputBuffer Buffer to store the result (a single status byte 0x00).
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the data written (always 1).
     * @throws ISOException If not initialized, locked, or authentication fails.
     */
    private short setPasswordInternal(byte[] authHashBuffer, short authHashOffset,
                                    byte[] newDerivedKeyBuffer, short newDerivedKeyOffset, short newDerivedKeyLength,
                                    byte[] outputBuffer, short outputOffset) throws ISOException {
        // Verify authentication hash (using *old* derived key, authenticating the *new* derived key)
        if (!verifyAuthHashInternal(authHashBuffer, authHashOffset, newDerivedKeyBuffer, newDerivedKeyOffset, newDerivedKeyLength)) {
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED);
        }
        
        try {
            // Authentication successful, copy new key and reset lock state
            Util.arrayCopyNonAtomic(newDerivedKeyBuffer, newDerivedKeyOffset, storedDerivedKey, (short)0, DERIVED_KEY_LENGTH);
            passwordTries = 0; // Reset password tries
            isLocked = false;  // Unlock card
            outputBuffer[outputOffset] = (byte)0x00; // Return success status byte
            return 1; 
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    /**
     * Internal handler for CMD_RESET.
     * Resets the card to its initial, uninitialized state after verifying authentication.
     * Generates a new key pair. Clears derived key, flags, status, counter, lock state.
     *
     * @param authHashBuffer Buffer containing the authentication hash.
     * @param authHashOffset Offset of the authentication hash.
     * @param dummyDataBuffer Buffer containing dummy data (used for authentication).
     * @param dummyDataOffset Offset of the dummy data.
     * @param dummyDataLength Length of the dummy data (must be RESET_DUMMY_DATA_LENGTH).
     * @param outputBuffer Buffer to store the result (a single status byte 0x00).
     * @param outputOffset Starting offset in the output buffer.
     * @return Length of the data written (always 1).
     * @throws ISOException If authentication fails. (Allows reset even if locked or uninitialized).
     */
    private short resetCardInternal(byte[] authHashBuffer, short authHashOffset,
                                  byte[] dummyDataBuffer, short dummyDataOffset, short dummyDataLength,
                                  byte[] outputBuffer, short outputOffset) throws ISOException {
        // Verify authentication hash (dummy data used)
        if (!verifyAuthHashInternal(authHashBuffer, authHashOffset, dummyDataBuffer, dummyDataOffset, dummyDataLength)) {
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED);
        }
        
        try {
            // Reset all state variables
            counter[0] = 0; counter[1] = 0; counter[2] = 0; counter[3] = 1; 
            configFlags = 0; // Not initialized, not exported
            configStatus = 0;
            Util.arrayFillNonAtomic(storedDerivedKey, (short)0, DERIVED_KEY_LENGTH, (byte)0); // Clear stored key
            passwordTries = 0;
            isLocked = false;
            generateNewKeyPairInternal(); // Generate a fresh key pair
            outputBuffer[outputOffset] = (byte)0x00; // Return success status byte
            return 1;
        } catch (Exception e) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }
        return 0; // Unreachable
    }

    // --- Internal Helper Methods ---

    /** Generates a new SECP256k1 key pair and sets the curve parameters. */
    private void generateNewKeyPairInternal() {
        keyPair = new KeyPair(KeyPair.ALG_EC_FP, KEY_SIZE);
        // SECP256k1 curve parameters must be set explicitly
        pubKey = (ECPublicKey)keyPair.getPublic();
        privKey = (ECPrivateKey)keyPair.getPrivate();
        SECP256k1.setCurveParameters(pubKey);
        SECP256k1.setCurveParameters(privKey);
        keyPair.genKeyPair(); // Generate the key pair
    }

    /** Increments the 4-byte counter atomically. */
    private void incrementCounterInternal() {
        short c = Util.getShort(counter, (short) 2);
        c++;
        Util.setShort(counter, (short) 2, c);
        if (c == 0) { // Handle carry-over to the upper two bytes
            c = Util.getShort(counter, (short) 0);
            c++;
            Util.setShort(counter, (short) 0, c);
        }
    }

    /**
     * Verifies the provided authentication hash against a computed hash.
     * The computed hash is SHA256(AUTH_PREFIX || AUTH_STRING || storedDerivedKey || dataToAuth).
     * Handles password try counting and locking.
     *
     * @param authHashBuffer Buffer containing the provided 32-byte authentication hash.
     * @param authHashOffset Offset of the provided hash.
     * @param dataToAuthBuffer Buffer containing the data that was authenticated.
     * @param dataToAuthOffset Offset of the data.
     * @param dataToAuthLength Length of the data.
     * @return true if the hash matches, false otherwise.
     * @throws ISOException ERR_CARD_LOCKED if locked,
     *                      ERR_NOT_INITIALIZED if not initialized,
     *                      ERR_AUTH_FAILED if hash mismatches (after incrementing tries),
     *                      ERR_CRYPTO_FAILED if computed hash length is wrong.
     */
    private boolean verifyAuthHashInternal(byte[] authHashBuffer, short authHashOffset,
                                           byte[] dataToAuthBuffer, short dataToAuthOffset, short dataToAuthLength)
                                           throws ISOException {

        // Check lock status
        if (isLocked) {
            ISOException.throwIt(CryptoErrors.ERR_CARD_LOCKED);
        }

        // Check initialization status
        if ((configFlags & FLAG_INITIALIZED) == 0) {
            ISOException.throwIt(CryptoErrors.ERR_NOT_INITIALIZED);
        }

        // Compute expected hash: SHA256(AUTH_PREFIX || AUTH_STRING || storedDerivedKey || dataToAuth)
        sha256.reset();
        sha256.update(AUTH_PREFIX, (short)0, (short)AUTH_PREFIX.length);
        sha256.update(AUTH_STRING, (short)0, (short)AUTH_STRING.length);
        sha256.update(dataToAuthBuffer, dataToAuthOffset, dataToAuthLength);
        sha256.update(storedDerivedKey, (short)0, DERIVED_KEY_LENGTH);

        // Use transient buffer for computed hash
        byte[] computedHash = JCSystem.makeTransientByteArray(AUTH_HASH_LENGTH, JCSystem.CLEAR_ON_DESELECT);
        short computedHashLen = sha256.doFinal(computedHash, (short)0, (short)0, computedHash, (short)0);

        // Check hash length after computation (should always be 32 for SHA-256)
        if (computedHashLen != AUTH_HASH_LENGTH) {
            ISOException.throwIt(CryptoErrors.ERR_CRYPTO_FAILED);
        }

        // Compare provided hash with computed hash
        boolean matches = Util.arrayCompare(authHashBuffer, authHashOffset,
                               computedHash, (short)0,
                               AUTH_HASH_LENGTH) == 0;

        if (!matches) {
            passwordTries++;
            if (passwordTries >= MAX_PASSWORD_TRIES) {
                isLocked = true;
                ISOException.throwIt(CryptoErrors.ERR_CARD_LOCKED);
            }
            ISOException.throwIt(CryptoErrors.ERR_AUTH_FAILED);
        }
        
        // Match successful
        passwordTries = 0; // Reset counter on success
        return true;
    }
}