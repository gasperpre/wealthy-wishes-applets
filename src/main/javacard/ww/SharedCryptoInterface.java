package main.javacard.ww;

import javacard.framework.Shareable;
import javacard.framework.ISOException;

/**
 * Interface defining shared cryptographic operations provided by CryptoHandler.
 */
public interface SharedCryptoInterface extends Shareable {

    /**
     * Processes a cryptographic command received via an applet.
     * The command byte is expected at commandDataOffset within commandDataBuffer.
     * The specific data for the command follows the command byte.
     * The implementation should handle authentication internally where required based on the command.
     *
     * @param commandDataBuffer Buffer containing the command byte and its associated data.
     * @param commandDataOffset Offset of the command byte within commandDataBuffer.
     * @param commandDataLength Total length of the command byte plus its data.
     * @param outputBuffer Buffer to store the raw result of the command (e.g., signature, public key, status).
     * @param outputOffset Starting offset in the output buffer.
     * @return The total length of the raw data written to the output buffer.
     * @throws ISOException if authentication fails, data is invalid, command is unknown, or other errors occur.
     */
    public short processCryptoCommand(byte[] commandDataBuffer, short commandDataOffset, short commandDataLength,
                               byte[] outputBuffer, short outputOffset) throws ISOException;

    /**
     * Retrieves the complete configuration data (version, flags, status, public key).
     *
     * @param outputBuffer Buffer to store the configuration bytes.
     * @param outputOffset Starting offset in the output buffer.
     * @return The length of the configuration data written.
     * @throws ISOException if an error occurs.
     */
    public short getConfig(byte[] outputBuffer, short outputOffset) throws ISOException;

    /**
     * Retrieves the current 4-byte counter value *after* the last successful signing operation (or initialization).
     * Used by U2fApplet to prepend to the signature response.
     *
     * @param buffer The buffer to copy the counter value into.
     * @param offset The starting offset in the buffer.
     * @return The length of the counter copied (always 4).
     */
    public short getLastCounterValue(byte[] buffer, short offset);
} 