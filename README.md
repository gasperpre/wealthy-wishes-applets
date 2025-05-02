# Wealthy Wishes JavaCard Applets

This project contains a collection of JavaCard applets designed to run on compatible smart cards, focusing on cryptographic functionalities accessible via NFC and standard APDU commands.

## Applets

The project builds a single CAP file (`WealthyWishesApplets.cap`) containing the following applets:

1.  **NDEF Applet (`main.javacard.ww.NDEFApplet`)**
    *   **AID:** `A000000647000001` (Uses standard NDEF AID `D2760000850101` for Type 4 Tag discovery)
    *   **Functionality:** Implements an NFC Forum Type 4 Tag. When read by an NFC device (like a smartphone), it presents an NDEF message containing a URL (`https://wealthy-wishes.vercel.app`). This URL dynamically includes cryptographic information (e.g., public keys, configuration, command results) retrieved from the `CryptoHandler` applet. Communication *to* the `CryptoHandler` (sending commands) is achieved by sending `UPDATE BINARY` commands to this NDEF applet.

2.  **U2F Applet (`main.javacard.ww.U2fApplet`)**
    *   **AID:** `A0000006472F0001`
    *   **Functionality:** Implements the interface for the FIDO U2F `SIGN` instruction (`INS=0x02`). However, instead of performing standard U2F signing based on the provided challenge and key handle, it acts as a channel to the `CryptoHandler` applet.

3.  **Crypto Handler Applet (`main.javacard.ww.CryptoHandler`)**
    *   **AID:** `A00000064743485F414944` (`CH_AID`)
    *   **Functionality:** A background applet responsible for managing cryptographic keys, performing signing operations, and maintaining state (like signature counters). It exposes its services to the `NDEFApplet` and `U2fApplet` via a JavaCard Shareable Interface Object (SIO) defined in `SharedCryptoInterface.java`. It is not typically selected directly but is called internally by the other applets.

## Building

The project uses Apache Ant and the `ant-javacard` task for building.

1.  **Prerequisites:**
    *   Apache Ant
    *   Java Development Kit (JDK) compatible with the JavaCard SDK version.
    *   JavaCard Development Kit 3.0.5u4 (Expected to be placed in the `sdks/jc305u4_kit` directory). You might need to download this separately from Oracle or other sources. Ensure the `sdks/` directory contains the necessary kit files.

2.  **Build Command:**
    ```bash
    ant build
    ```
    Or simply:
    ```bash
    ant
    ```
    This will compile the Java source files and create the `WealthyWishesApplets.cap` file in the project's root directory.

## Installation

The resulting `WealthyWishesApplets.cap` file can be installed onto a compatible JavaCard smart card using appropriate card management tools (e.g., GlobalPlatformPro). Ensure you install all three applets defined in the CAP file.
