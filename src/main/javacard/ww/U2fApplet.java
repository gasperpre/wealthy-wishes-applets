package main.javacard.ww;

import javacard.framework.*;
import javacardx.apdu.ExtendedLength;

public class U2fApplet extends Applet implements ExtendedLength {

    /** Applet Instance AID: A0000006472F0001 */
    public static final byte[] AID_BYTES = {
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x47,
        (byte)0x2F, (byte)0x00, (byte)0x01
    };

    /** AID for the CryptoHandler Applet (must match CryptoHandler.AID_BYTES). */
    private static final byte[] CRYPTO_HANDLER_AID_BYTES = {
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x47,
        (byte)0x43, (byte)0x48, (byte)0x5F, (byte)0x41, (byte)0x49, (byte)0x44
    };
    private AID cryptoHandlerAID;
    /** Shareable Interface Object for communicating with CryptoHandler. */
    private SharedCryptoInterface cryptoHandlerSIO;

    // Constants
    private static final byte VERSION[] = {'U', '2', 'F', '_', 'V', '2'};
    private static final byte CLA_U2F = (byte) 0x00;
    private static final byte U2F_INS_SIGN = (byte) 0x02;
    private static final byte U2F_INS_VERSION = (byte) 0x03;
    private static final byte P1_SIGN = (byte) 0x03;
    private static final byte P1_CHECK_ONLY = (byte) 0x07;
    private static final byte CTAP2_CLA = (byte) 0x80;
    private static final byte CTAP2_INS_GET_INFO = (byte) 0x10;
    private static final byte[] CTAP2_INS_GET_INFO_RESPONSE = {0x00, (byte)0xA1, 0x01,(byte) 0x81, 0x66, 0x55, 0x32, 0x46, 0x5F, 0x56, (byte)0x32};
    private static final byte ISO_CLA = (byte) 0x00;
    private static final byte ISO_INS_GET_DATA = (byte) 0xC0;
    private static final byte OFFSET_KEY_HANDLE = 65; // Offset within SIGN command data

    // Transport states for GET RESPONSE handling
    private static final byte TRANSPORT_NONE = (byte) 0;       // No chunked response pending
    private static final byte TRANSPORT_EXTENDED = (byte) 1;   // Extended length response sent
    private static final byte TRANSPORT_NOT_EXTENDED = (byte) 2; // Chunked response pending (GET RESPONSE needed)

    // Scratchpad layout (transient memory)
    private static final byte SCRATCH_TRANSPORT_STATE = (byte) 0; // Stores current transport state (TRANSPORT_*)
    private static final byte SCRATCH_CURRENT_OFFSET = (byte) 1;  // Offset for chunked response (2 bytes)
    private static final byte SCRATCH_FULL_LENGTH = (byte) 3;     // Full length of chunked response (2 bytes)
    private static final byte SCRATCH_PAD_OFFSET = (byte) 5;      // Start of actual response data in scratch
    private static final short SCRATCH_BUFFER_SIZE = 128;        // Size of the scratch buffer

    // Response prefix constants for SIGN command
    private static final byte PRESENCE_BYTE = (byte)0x01; // User presence confirmed
    private static final short PRESENCE_LENGTH = 1;
    private static final short COUNTER_LENGTH = 4;       // Signature counter length

    // Instance variables
    private byte[] scratch; // Transient buffer for temporary data and chunked responses

    private U2fApplet() {
        // Allocate scratch buffer first
        scratch = JCSystem.makeTransientByteArray(SCRATCH_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);
        scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE; 
        
        cryptoHandlerSIO = null; // Initialize SIO reference to null
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new U2fApplet().register(AID_BYTES, (short)0, (byte)AID_BYTES.length);
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        if (selectingApplet()) {
            // Return U2F version on selection
            Util.arrayCopyNonAtomic(VERSION, (short) 0, buffer, (short) 0, (short) VERSION.length);
            apdu.setOutgoingAndSend((short) 0, (short) VERSION.length);
            // Reset state on re-selection
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;
            cryptoHandlerSIO = null; // Force SIO re-lookup on next command
            return;
        }

        // Retrieve SIO for CryptoHandler if not already done in this session
        if (cryptoHandlerSIO == null) {
            cryptoHandlerAID = JCSystem.lookupAID(CRYPTO_HANDLER_AID_BYTES, (short)0, (byte)CRYPTO_HANDLER_AID_BYTES.length);
            if (cryptoHandlerAID == null) {
                // CryptoHandler applet not found/installed
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
             cryptoHandlerSIO = (SharedCryptoInterface) JCSystem.getAppletShareableInterfaceObject(cryptoHandlerAID, (byte) 0x00);
             if (cryptoHandlerSIO == null) {
                // Could not get SIO from CryptoHandler (e.g., not installed, security issue)
                 ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
             }
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Handle GET RESPONSE first if a chunked response is pending
        if (scratch[SCRATCH_TRANSPORT_STATE] == TRANSPORT_NOT_EXTENDED &&
            cla == ISO_CLA && ins == ISO_INS_GET_DATA) {
            handleGetData(apdu);
            return;
        }

        // Reset transport state before processing a new command (unless it was GET RESPONSE)
        scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;

        // Check supported CLAs
        if (cla != CLA_U2F && cla != CTAP2_CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        // Handle supported INS
        switch (ins) {
            case U2F_INS_SIGN:
                handleSign(apdu);
                break;
            case U2F_INS_VERSION:
                handleVersion(apdu);
                break;
            case CTAP2_INS_GET_INFO:
            	handleGetInfo(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Handles the U2F_INS_SIGN command.
     * Delegates cryptographic signing to the CryptoHandler applet via SIO.
     * Formats the response (presence byte, counter, signature).
     * Handles transport layer (extended length or chunked response).
     *
     * @param apdu The APDU object.
     * @throws ISOException If parameters are incorrect or crypto operation fails.
     */
    private void handleSign(APDU apdu) throws ISOException {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];

        short dataLen = apdu.setIncomingAndReceive();
        short dataOffset = apdu.getOffsetCdata(); 
        
        if (p1 == P1_CHECK_ONLY) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        
        if (p1 != P1_SIGN) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        // Ensure data length is sufficient to contain the key handle offset
        if (dataLen < OFFSET_KEY_HANDLE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Delegate signing to CryptoHandler via SIO
        // Response format: [Presence(1)] [Counter(4)] [Signature(var)]
        short prefixLength = PRESENCE_LENGTH + COUNTER_LENGTH;
        short rawResponseOffset = (short)(SCRATCH_PAD_OFFSET + prefixLength); // Where signature goes in scratch
        short rawResponseLength = cryptoHandlerSIO.processCryptoCommand(
            buf, (short)(dataOffset + OFFSET_KEY_HANDLE), (short)(dataLen - OFFSET_KEY_HANDLE), // Pass key handle + challenge + app ID hash
            scratch, rawResponseOffset // Output buffer (scratchpad) and offset
        );

        // Get the updated counter value from CryptoHandler
        cryptoHandlerSIO.getLastCounterValue(scratch, (short)(SCRATCH_PAD_OFFSET + PRESENCE_LENGTH)); // Write counter after presence byte
        scratch[SCRATCH_PAD_OFFSET] = PRESENCE_BYTE; // Set presence byte

        short totalResponseLength = (short)(prefixLength + rawResponseLength);

        // Send Response (Handle Transport: Extended Length or Chunked)
        boolean useExtended = false;
        try {
             short Le = apdu.setOutgoing();
             // Check if the host requested extended length (T=1 specific check)
             if (Le > 255) {
                 useExtended = true;
             }
        } catch (Exception e) { /* Ignore potential exceptions during Le check */ }

        if (useExtended) {
            // Send full response using extended length
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_EXTENDED;
            apdu.setOutgoingLength(totalResponseLength);
            apdu.sendBytesLong(scratch, SCRATCH_PAD_OFFSET, totalResponseLength);
        } else {
            // Prepare for chunked response using GET RESPONSE (INS 0xC0)
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NOT_EXTENDED;
            Util.setShort(scratch, SCRATCH_FULL_LENGTH, totalResponseLength); // Store total length
            Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, (short) 0);       // Reset chunk offset
            handleGetData(apdu); // Send the first chunk
        }
    }

    /**
     * Handles the GET RESPONSE command (INS 0xC0) for sending chunked data
     * when the response doesn't fit in a short APDU and extended length isn't used.
     * Reads data from the scratch buffer based on stored state.
     *
     * @param apdu The APDU object.
     * @throws ISOException If state is invalid or offset is wrong.
     */
    private void handleGetData(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        short requestedSize = apdu.setOutgoing(); // Le field indicates max size host expects

        // Clamp requested size to max short APDU data size (256)
        if (requestedSize > 256) requestedSize = 256;
        if (requestedSize == 0) requestedSize = 256; // Le=0 means request max possible (256 for short APDU)

        // Retrieve state from scratchpad
        short currentOffset = Util.getShort(scratch, SCRATCH_CURRENT_OFFSET);
        short totalLength = Util.getShort(scratch, SCRATCH_FULL_LENGTH);
        short remainingLength = (short)(totalLength - currentOffset);

        if (remainingLength <= 0) {
            // Should not happen if state is managed correctly
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); // Or conditions not satisfied
        }

        // Determine size of this chunk
        short blockSize = (remainingLength > requestedSize ? requestedSize : remainingLength);

        // Copy chunk from scratchpad to APDU buffer
        Util.arrayCopyNonAtomic(scratch, (short)(SCRATCH_PAD_OFFSET + currentOffset),
                                buffer, (short) 0, blockSize);

        apdu.setOutgoingLength(blockSize);
        apdu.sendBytes((short) 0, blockSize);

        // Update state in scratchpad
        currentOffset += blockSize;
        Util.setShort(scratch, SCRATCH_CURRENT_OFFSET, currentOffset);
        remainingLength -= blockSize;

        if (remainingLength == 0) {
            // All data sent, reset transport state
            scratch[SCRATCH_TRANSPORT_STATE] = TRANSPORT_NONE;
            // SW_NO_ERROR is sent implicitly by sendBytes
        } else {
            // More data remaining, signal with SW_BYTES_REMAINING_00
            // Clamp remaining length to 255 for status word encoding
            if (remainingLength > 255) remainingLength = 255;
            ISOException.throwIt((short)(ISO7816.SW_BYTES_REMAINING_00 | remainingLength));
        }
    }

    /**
     * Handles the U2F_INS_VERSION command.
     * Returns the static U2F version string.
     *
     * @param apdu The APDU object.
     */
    private void handleVersion(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(VERSION, (short) 0, buffer, (short) 0, (short) VERSION.length);
        apdu.setOutgoingAndSend((short) 0, (short) VERSION.length);
    }

    /**
     * Handles the CTAP2_INS_GET_INFO command.
     * Returns a static response indicating U2F V2 support.
     *
     * @param apdu The APDU object.
     */
    private void handleGetInfo(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        Util.arrayCopyNonAtomic(CTAP2_INS_GET_INFO_RESPONSE, (short)0, buffer, (short) 0, (short) CTAP2_INS_GET_INFO_RESPONSE.length);
        apdu.setOutgoingAndSend((short) 0, (short) CTAP2_INS_GET_INFO_RESPONSE.length);
    }
}