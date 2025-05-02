package main.javacard.ww;

import javacard.framework.Util;

/**
 * Custom error codes for crypto operations
 */
public class CryptoErrors {
    // Base error code for crypto operations (to avoid conflicts with ISO7816 codes)
    private static final short BASE_ERROR = (short) 0x7000;

    // Authentication errors
    public static final short ERR_AUTH_FAILED = (short) (BASE_ERROR + 0x01);
    public static final short ERR_CARD_LOCKED = (short) (BASE_ERROR + 0x02);
    public static final short ERR_NOT_INITIALIZED = (short) (BASE_ERROR + 0x03);
    public static final short ERR_ALREADY_INITIALIZED = (short) (BASE_ERROR + 0x04);

    // Operation errors
    public static final short ERR_INVALID_LENGTH = (short) (BASE_ERROR + 0x10);
    public static final short ERR_INVALID_COMMAND = (short) (BASE_ERROR + 0x11);
    public static final short ERR_CRYPTO_FAILED = (short) (BASE_ERROR + 0x12);
    public static final short ERR_EXPORT_FAILED = (short) (BASE_ERROR + 0x13);

    /**
     * Writes error code to the output buffer
     * Format: [ErrorCode(2)]
     * @param buffer Output buffer
     * @param offset Offset in buffer
     * @param errorCode Error code
     * @return Length of written data (always 2)
     */
    public static short writeError(byte[] buffer, short offset, short errorCode) {
        Util.setShort(buffer, offset, errorCode);
        return 2;
    }

    /**
     * Checks if a given short is an error code
     * @param code Code to check
     * @return true if code is in error range
     */
    public static boolean isError(short code) {
        return (code >= BASE_ERROR) && (code <= (short)(BASE_ERROR + 0xFF));
    }
} 