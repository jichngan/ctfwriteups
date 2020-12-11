# Steganography Guide 

## PNG Files
### pngcheck
- Run `pngcheck` on PNG files to check for missing chunks or text chunks 
- `pngcheck -cvt [PNG_File]`

### `tEXt` and `zTXt` chunks
- These two chunks can store text information inside PNG files 
- [Text Chunk Decoder](https://www.dcode.fr/png-chunks)
- Use the website to extract the chunk 
- Proceed to CyberChef to convert extracted chunk and save as `.PNG` file. Chunk might be encoded in `base64`

