package main.javacard.ww;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * NDEF Applet implementing the NFC Forum Type 4 Tag specification.
 * Provides read-only access to NDEF data containing a URL.
 * The URL includes dynamic data (public key, configuration, command results)
 * retrieved from the CryptoHandler applet via a Shareable Interface Object (SIO).
 * UPDATE BINARY commands are used as a channel to send commands to the CryptoHandler.
 */
public final class NDEFApplet extends Applet {

    /** NDEF AID (D2760000850101) - Standard Type 4 Tag Applet */
    private static final byte[] NDEF_APPLET_AID_BYTES = {
        (byte)0xD2, (byte)0x76, (byte)0x00, (byte)0x00, 
        (byte)0x85, (byte)0x01, (byte)0x01
    };

    /** AID of the CryptoHandler Applet ("CH_AID") */
    private static final byte[] CRYPTO_HANDLER_AID_BYTES = {
        (byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x06, (byte)0x47, 
        (byte)0x43, (byte)0x48, (byte)0x5F, (byte)0x41, (byte)0x49, (byte)0x44 
    };

    /** File ID for NDEF Capability Container (CC) file. */
    private static final short FILEID_NDEF_CAPABILITIES = (short)0xE103;
    /** File ID for the main NDEF data file. */
    private static final short FILEID_NDEF_DATA = (short)0xE104;

    /** Base URL for the web application (without parameters). */
    private static final byte[] WEBAPP_URL = {
		(byte)0x68, (byte)0x74, (byte)0x74, (byte)0x70, // "http"
        (byte)0x73, (byte)0x3A, (byte)0x2F, (byte)0x2F, // "s://"
        (byte)0x77, (byte)0x65, (byte)0x61, (byte)0x6C, // "weal"
        (byte)0x74, (byte)0x68, (byte)0x79, (byte)0x2D, // "thy-"
        (byte)0x77, (byte)0x69, (byte)0x73, (byte)0x68, // "wish"
        (byte)0x65, (byte)0x73, (byte)0x2E, (byte)0x76, // "es.v"
        (byte)0x65, (byte)0x72, (byte)0x63, (byte)0x65, // "erce"
        (byte)0x6C, (byte)0x2E, (byte)0x61, (byte)0x70, // "l.ap"
        (byte)0x70                                       // "p"                      
    };
    
    /** Buffer to hold the dynamically generated NDEF message. */
    private byte[] ndefDataBuffer;
    /** Maximum size of the NDEF data buffer. */
    private static final short NDEF_BUFFER_MAX_SIZE = 1024;
    /** Maximum bytes allowed per READ/WRITE operation (as per CC file). */
    private static final short NDEF_MAX_READ_WRITE = 128;
    
    /** Buffer to store the response data from CryptoHandler commands. */
    private byte[] responseData;
    /** Length of the valid data currently in responseData. */
    private short responseDataLength;
    /** Maximum size of the response data buffer. */
    private static final short RESPONSE_DATA_MAX_SIZE = 512;

    /**
     * Capability Container (CC) file content.
     * Defines NDEF mapping version, max read/write sizes, and NDEF file info.
     */
    private static final byte[] CC_FILE = {
        (byte)0x00, (byte)0x0F, // CCLEN (15 bytes)
        (byte)0x20,             // Mapping Version 2.0
        (byte)((NDEF_MAX_READ_WRITE >> 8) & 0xFF), (byte)(NDEF_MAX_READ_WRITE & 0xFF), // MLe (max R-APDU)
        (byte)((NDEF_MAX_READ_WRITE >> 8) & 0xFF), (byte)(NDEF_MAX_READ_WRITE & 0xFF), // MLc (max C-APDU)
        (byte)0x04,             // NDEF File Control TLV tag
        (byte)0x06,             // Length = 6 bytes
        (byte)0xE1, (byte)0x04, // NDEF File ID (E104)
        (byte)(NDEF_BUFFER_MAX_SIZE >> 8), (byte)(NDEF_BUFFER_MAX_SIZE & 0xFF), // Max NDEF file size (Placeholder - updated dynamically)
        (byte)0x00,             // Read Access (granted without security)
        (byte)0x00              // Write Access (granted without security for UPDATE BINARY)
    };

    /** Currently selected file ID (CC or NDEF data), or -1 if none. */
    private short selectedFile;
    
    /** Shareable Interface Object for communicating with CryptoHandler. */
    private SharedCryptoInterface cryptoHandlerSIO;
    /** AID object for the CryptoHandler applet. */
    private AID cryptoHandlerAID;
    
    /** Transient buffer for hex conversion and temporary crypto results. */
    private byte[] transientUtilBuffer;
    /** Size of the transient utility buffer. */
    private static final short TRANSIENT_UTIL_BUFFER_SIZE = 256; // Increased to handle larger chunks
    

    /** Hexadecimal characters for byte-to-hex conversion. */
    private static final byte[] HEX_CHARS = {
        (byte)'0', (byte)'1', (byte)'2', (byte)'3', (byte)'4', (byte)'5', (byte)'6', (byte)'7',
        (byte)'8', (byte)'9', (byte)'a', (byte)'b', (byte)'c', (byte)'d', (byte)'e', (byte)'f' };

    /**
     * Installs the NDEF applet. Called by the JCRE.
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the parameter data in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new NDEFApplet().register(NDEF_APPLET_AID_BYTES, (short)0, (byte)NDEF_APPLET_AID_BYTES.length);
    }

    /**
     * Private constructor for the applet. Initializes state.
     */
    private NDEFApplet() {
        selectedFile = -1; 
        
        // Persistent buffer for the NDEF message itself
        ndefDataBuffer = new byte[NDEF_BUFFER_MAX_SIZE];
        // Persistent buffer for the response data
        responseData = new byte[RESPONSE_DATA_MAX_SIZE];
        responseDataLength = 0;
        // Transient buffer for temporary calculations
        transientUtilBuffer = JCSystem.makeTransientByteArray(TRANSIENT_UTIL_BUFFER_SIZE, JCSystem.CLEAR_ON_DESELECT);

        // SIO is retrieved later when needed
        cryptoHandlerSIO = null;
        
        // Create initial NDEF message with just the base URL
        createNdefUrlResponse(); 
    }

    /**
     * Processes an incoming APDU command.
     * Handles SELECT, READ BINARY, and UPDATE BINARY (for crypto commands).
     * @param apdu The incoming APDU object.
     */
    @Override
    public void process(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();
        
        if (selectingApplet()) {
            selectedFile = -1;
            cryptoHandlerSIO = null;
            return;
        }

        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        // Standard NDEF Type 4 tag command processing
        if (cla != ISO7816.CLA_ISO7816) {
             ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        
        // --- Get SIO if needed --- 
        if (cryptoHandlerSIO == null) {
            // Lookup CryptoHandler AID
            cryptoHandlerAID = JCSystem.lookupAID(CRYPTO_HANDLER_AID_BYTES, (short)0, (byte)CRYPTO_HANDLER_AID_BYTES.length);
            if (cryptoHandlerAID == null) {
            	// Handle error: CryptoHandler applet not found/installed
            	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
             cryptoHandlerSIO = (SharedCryptoInterface) JCSystem.getAppletShareableInterfaceObject(cryptoHandlerAID, (byte) 0x00);
             if (cryptoHandlerSIO == null) {
                // Handle error: Could not get SIO from CryptoHandler
                 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
             }
        }
        // --- End SIO retrieval ---
        
        switch(ins) {
            case ISO7816.INS_SELECT: // Select File
                processSelect(apdu);
                break;
            case (byte)0xB0: // Read Binary
                 processReadBinary(apdu);
                break;
             case (byte)0xD6: // Update Binary (used to send commands to CryptoHandler)
                 processUpdateBinary(apdu);
                 break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    /**
     * Handles the SELECT instruction. Selects either the CC file or the NDEF data file.
     * @param apdu The APDU object containing the SELECT command.
     */
    private void processSelect(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short fileId = Util.getShort(buffer, ISO7816.OFFSET_CDATA);

        if(fileId == FILEID_NDEF_CAPABILITIES) {
            selectedFile = fileId;
        } else if (fileId == FILEID_NDEF_DATA) {
        	// Update the NDEF message buffer with the new response data
            // The raw data is in responseData[0...responseDataLength-1]
            createNdefUrlResponse();
            selectedFile = fileId;
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    /**
     * Handles the READ BINARY instruction. Reads data from the currently selected file.
     * @param apdu The APDU object containing the READ BINARY command.
     * @throws ISOException If file not selected, offset/length invalid, or other errors occur.
     */
    private void processReadBinary(APDU apdu) throws ISOException {
        byte[] buffer = apdu.getBuffer();

        // access the file
        byte[] sourceData;
        short sourceLength;

        switch (selectedFile) {
            case FILEID_NDEF_CAPABILITIES:
                sourceData = CC_FILE;
                sourceLength = (short)CC_FILE.length;
                break;
            case FILEID_NDEF_DATA:
                sourceData = ndefDataBuffer;
                sourceLength = NDEF_BUFFER_MAX_SIZE;
                break;
            default:
                 ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // No file selected
                 return; // Unreachable but good practice
        }

        // get and check the read offset
        short offset = Util.getShort(buffer, ISO7816.OFFSET_P1);
        if(offset < 0 || offset >= sourceLength) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }

        // determine the output size
        short le = apdu.setOutgoingNoChaining();
        if(le > NDEF_MAX_READ_WRITE) {
            le = NDEF_MAX_READ_WRITE;
        }

        // adjust for end of file
        short limit = (short)(offset + le);
        if(limit < 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if(limit >= sourceLength) {
            le = (short)(sourceLength - offset);
        }

        // send the requested data
        apdu.setOutgoingLength(le);
        apdu.sendBytesLong(sourceData, offset, le);
    }
    
    /**
     * Handles UPDATE BINARY. This command is repurposed to send commands to the CryptoHandler.
     * The command data is expected in the APDU data field.
     * The result from CryptoHandler is stored in `responseData` for later inclusion in the NDEF URL.
     * @param apdu The APDU object containing the UPDATE BINARY command and crypto data.
     */
    private void processUpdateBinary(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive(); // This is the crypto command + data
        short dataOffset = apdu.getOffsetCdata(); // Where the crypto command starts

        if (selectedFile != FILEID_NDEF_DATA) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); // Must select NDEF file first
        }

        if (cryptoHandlerSIO == null) { 
            // If U2fApplet wasn't found during init, this will fail
             ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED); 
        }

        if (bytesRead > 3) {
            // --- Delegate directly to CryptoHandler via Shared Interface --- 
        	try {
	            responseDataLength = cryptoHandlerSIO.processCryptoCommand(
	                buffer,       // APDU buffer contains the crypto command
	                (short)(dataOffset + 3),   // Offset of the crypto command byte
	                (short)(bytesRead - 3),    // Total length (crypto command byte + its data)
	                responseData, // Store raw output here
	                (short)0      // Offset in output
	            );
        	} catch(ISOException e) {
                if (e.getReason() == ISO7816.SW_WRONG_LENGTH) {
                    // Handle wrong length specifically
                    return;
                }
                // Re-throw other ISO exceptions
                throw e;
        	}
            // --- End Delegation --- 
        }
    }

    /**
     * Creates or updates the NDEF message in `ndefDataBuffer`.
     * The message contains a URL with query parameters for configuration (`cfg`)
     * and the latest command response (`d`).
     */
    private void createNdefUrlResponse() {
        // NDEF message construction starts after 2-byte NLEN field
        short writeOffset = 2; 
        short configLen = 0; // Changed from pkLen
        boolean configAvailable = false; // Changed from keyAvailable
        boolean dataAvailable = (responseData != null && responseDataLength > 0);

        // Try to get public key bytes via SIO if available
        if (cryptoHandlerSIO != null) {
            try {
                // Use transient buffer temporarily to store complete config bytes
                configLen = cryptoHandlerSIO.getConfig(transientUtilBuffer, (short)0); // Call getConfig
                configAvailable = (configLen > 0);
            } catch (ISOException e) {
                // Ignore potential errors (like U2fApplet not initialized yet)
                configAvailable = false;
            } catch (Exception e) { // Catch broader exceptions just in case
                configAvailable = false;
            }
        }
        
        // Prepare hex lengths for payload calculation
        short hexCfgLen = configAvailable ? (short)(configLen * 2) : 0;
        short hexDataLen = dataAvailable ? (short)(responseDataLength * 2) : 0;

        // --- Calculate Payload Length beforehand ---
        short payloadLength = 1; // URI Identifier Code (0x00)
        payloadLength += (short)WEBAPP_URL.length;
        byte separator = (byte)'?';
        if (configAvailable) {
            // Parameter "cfg" (3 letters) instead of "pk" (2 letters)
            payloadLength += (short)(1 + 3 + 1 + hexCfgLen); // separator + "cfg" + "=" + hexCfgLen
            separator = (byte)'&';
        }
        if (dataAvailable) {
            payloadLength += (short)(1 + 1 + 1 + hexDataLen); // separator + "d" + "=" + hexDataLen
        }

        // --- Check if total message will exceed buffer ---
        // Header size depends on payloadLength
        short headerSize = (payloadLength <= 255) ? (short)4 : (short)7;
        short totalMessageLength = (short)(headerSize + payloadLength);
        if ((short)(totalMessageLength + 2) > NDEF_BUFFER_MAX_SIZE) {
            // Message + NLEN exceeds buffer
            ISOException.throwIt(ISO7816.SW_FILE_FULL); // Or a more appropriate error
        }
        
        // --- Start building NDEF message in ndefDataBuffer --- 
        
        // NDEF Record Header
        // bit 7 = MB (1 = Message Begin)
        // bit 6 = ME (1 = Message End)
        // bit 5 = CF (0 = Not a chunk)
        // bit 4 = SR (1 = Short Record, 0 = Standard Record)
        // bit 3 = IL (0 = No ID field)
        // bits 2-0 = TNF (0x01 = Well Known Type)
        if (payloadLength <= 255) {
            // Use Short Record (SR=1)
            ndefDataBuffer[writeOffset++] = (byte)0xD1; // 11010001b = MB,ME,SR,TNF=1
            ndefDataBuffer[writeOffset++] = (byte)0x01; // Type Length = 1 ('U')
            ndefDataBuffer[writeOffset++] = (byte)payloadLength; // Payload length (1 byte)
        } else {
            // Use Standard Record (SR=0)
            ndefDataBuffer[writeOffset++] = (byte)0xC1; // 11000001b = MB,ME,TNF=1
            ndefDataBuffer[writeOffset++] = (byte)0x01; // Type Length = 1 ('U')
            // Payload length (4 bytes, Big Endian)
            // For JavaCard, we need to handle this carefully since shorts are signed
            ndefDataBuffer[writeOffset++] = (byte)0x00; // Most significant byte is always 0 (we won't exceed 65535)
            ndefDataBuffer[writeOffset++] = (byte)0x00; // Second byte is always 0 (we won't exceed 65535)
            ndefDataBuffer[writeOffset++] = (byte)(payloadLength >> 8); // High byte
            ndefDataBuffer[writeOffset++] = (byte)(payloadLength & 0xFF); // Low byte
        }
        ndefDataBuffer[writeOffset++] = (byte)0x55; // Type = 'U' (URI)
        
        // --- Write URI Payload ---
        ndefDataBuffer[writeOffset++] = (byte)0x00; // URI Identifier Code (0x00 = No prefix)

        // Copy base URL
        Util.arrayCopyNonAtomic(WEBAPP_URL, (short)0, ndefDataBuffer, writeOffset, (short)WEBAPP_URL.length);
        writeOffset += (short)WEBAPP_URL.length;
        
        // Add query parameters (?pk=...&d=...)
        separator = (byte)'?'; // Reset separator for writing
        
        // Append pk parameter if key is available
        if (configAvailable) {
            ndefDataBuffer[writeOffset++] = separator;
            ndefDataBuffer[writeOffset++] = (byte)'c'; // Use 'c'
            ndefDataBuffer[writeOffset++] = (byte)'f'; // Use 'f'
            ndefDataBuffer[writeOffset++] = (byte)'g'; // Use 'g'
            ndefDataBuffer[writeOffset++] = (byte)'=';
            // Write hex-encoded configuration directly into ndefDataBuffer
            short writtenCfg = bytesToHex(transientUtilBuffer, (short)0, configLen, ndefDataBuffer, writeOffset);
            writeOffset += writtenCfg;
            separator = (byte)'&';
        }
        
        // Append d parameter if response data exists
        if (dataAvailable) {
            ndefDataBuffer[writeOffset++] = separator;
            ndefDataBuffer[writeOffset++] = (byte)'d';
            ndefDataBuffer[writeOffset++] = (byte)'=';
            // Write hex-encoded responseData directly into ndefDataBuffer
            short writtenData = bytesToHex(responseData, (short)0, responseDataLength, ndefDataBuffer, writeOffset);
            writeOffset += writtenData;
        }

        
        // Calculate total NDEF message length (excluding the 2 NLEN bytes)
        // This should match the pre-calculated headerSize + payloadLength
        short actualMessageLength = (short)(writeOffset - 2);

        // Update NLEN (2 bytes, Big Endian) with the *actual* message length
       ndefDataBuffer[0] = (byte)(actualMessageLength >> 8);
       ndefDataBuffer[1] = (byte)(actualMessageLength & 0xFF);
        
        // Pad the buffer to max size
        short paddingLength = (short)(NDEF_BUFFER_MAX_SIZE - writeOffset);
        
        if (paddingLength > 0) {
            // Fill the remaining buffer with zeros
            Util.arrayFillNonAtomic(ndefDataBuffer, writeOffset, paddingLength, (byte)0x00);
        }
    }

    /**
     * Converts a byte array segment into its hexadecimal string representation.
     * Writes the result directly into the output buffer.
     *
     * @param bytesIn   The input byte array.
     * @param offIn     The starting offset in the input array.
     * @param lenIn     The number of bytes to convert.
     * @param hexOut    The output buffer for the hex string.
     * @param offOut    The starting offset in the output buffer.
     * @return The number of bytes written to `hexOut` (which is `lenIn * 2`).
     * @throws ISOException If the output buffer is too small or other errors occur.
     */
    private short bytesToHex(byte[] bytesIn, short offIn, short lenIn,
                             byte[] hexOut, short offOut) 
                             throws ISOException {
        // Check if output buffer has enough space
        if ((short)(offOut + (lenIn * 2)) > (short)hexOut.length || (short)(lenIn * 2) < 0) { // Check for overflow in lenIn*2
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH); 
        }
        short hexIndex = offOut;
        short endIn = (short)(offIn + lenIn);
        for (short i = offIn; i < endIn; i++) {
            byte b = bytesIn[i];
            hexOut[hexIndex++] = HEX_CHARS[(byte)((b >> 4) & 0x0F)]; // High nibble
            hexOut[hexIndex++] = HEX_CHARS[(byte)(b & 0x0F)];      // Low nibble
        }
        return (short)(lenIn * 2); // Return number of hex bytes written
    }
}