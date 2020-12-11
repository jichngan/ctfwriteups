# Image File Guide 
- This is a collection of tools/guides to do when encountering an image file 
- This includes stego and also other tools 

## PNG Files
### pngcheck
- Run `pngcheck` on PNG files to check for missing chunks or text chunks 
- `pngcheck -cvt [PNG_File]`

### `tEXt` and `zTXt` chunks
- These two chunks can store text information inside PNG files 
- [Text Chunk Decoder](https://www.dcode.fr/png-chunks)
- Use the website to extract the chunk 
- Proceed to CyberChef to convert extracted chunk and save as `.PNG` file. Chunk might be encoded in `base64`

## Steghide 
- Steghide is a steganography program that can reveal image steganography with a password 
- Can also supply **NO PASSWORD** so can try this first 
- `steghide extract -sf [File_Name] -p [Password]`

## Binary (0,1) to image
- A **text file** containing 0s and 1s can contain a QR Code 
- Go to this [link](https://www.dcode.fr/binary-image) to convert
- Example of this is HTB Digital Cube Challenge 
