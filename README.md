# I2C STUSB4500
## ===========================================================

This High level Analyzer is displaying information that is exchanged between an STUSB4500 and an MCU (like an Arduino) on the I2C.
It will decode (as much as possible) the data that is read/written to a register on the STUSB4500. With the data read from an STUSB4500 register, it will try to decode what is known or else the raw received data is displayed. Also the NVM data is provided only as raw data.

Finding the exact right description for each register is a HUGE challenge. Different documentation, different source files, different header files are not 100% in sync, but this is the best I could get to (for now). Who knows what we learn in the future.

For analysing the USB-PD data between de STUSB4500-SINK and USB-PD power supply there is already another HLA [https://github.com/saleae/hla-usb-pd](https://github.com/saleae/hla-usb-pd/). This can be selected as extension in Saleae as well.

Please report problems or additional information / remarks on github

## Prerequisites
Make sure you have a Saleae analyzer and software. This has been tested with a Saleae Logic 8
During my testing I have made use of the [SparkFun Power Delivery Board - USB-C (Qwiic)](https://www.sparkfun.com/products/15801). I have used their library as well, although there a many others on github.

## Software installation
If this analyser can not be selected through the ![Saleae interface](https://support.saleae.com/extensions/installing-extensions), or you want to make adjustments perform the following steps:

1. Create a new local extension follow instructions: [https://support.saleae.com/extensions/extensions-quickstart](https://support.saleae.com/extensions/extensions-quickstart)
2. As part of the creation, you want be asked which folder you want to use.
3. Copy / overwrite the 3 files : HighLevelAnalyzer.py, README.md and extension.json from this library in that folder.
4. Restart the Saleae software and you should be able to see this HLA as local extension.

## Getting Started

1. Select and sestup the I2C-signal analyzer from Saleae.
2. Add the I2c STUSB4500 Analyzer and select the I2C-signal analyzer as the input

## Versioning

### version 1.0.0 / October 2022
 * Initial version

## Author
 * Paul van Haastrecht (paulvha@hotmail.com)

## Acknowledgments
For reference I have included in [extras folder](./extras) most relevant information I had.
