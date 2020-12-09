# Topic: Memory Forensic
# Solve: After Competition 

## Challenge 
We were provided with a `.mem` file which hinted at memory forensics. As this is also the first few times I used the `Volatility` framework, I have a lot to learn. 

## Tools
I chose to use Volatility 2 framework instead of 3 due to the extension plugins avaialble for it at the moment. 

## Solving 
1. As with any memory forensics analysis, we will start with an `imageinfo` scan 
```
python vol.py -f ~/Downloads/forensics-challenge-1.mem imageinfo
```
```
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_24000, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_24000, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : FileAddressSpace (/Users/jichngan/Downloads/forensics-challenge-1.mem)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800029fb0a0L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff800029fcd00L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2020-12-03 09:12:22 UTC+0000
     Image local date and time : 2020-12-03 17:12:22 +0800
```
As seen from the suggested profile, `Win7SP1x64` is the suggested one. So we will use that for future analysis. 

2. We will continue this with a `pstree` to scan for the process on the memory.

```
python vol.py -f ~/Downloads/forensics-challenge-1.mem --profile=Win7SP1x64 pstree
```
There were a few processes but a few of them stood out to me.

```
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa801a3dd7f0:explorer.exe                     2460   2432     32    905 2020-12-03 08:51:58 UTC+0000
. 0xfffffa801aed8060:notepad.exe                     3896   2460      5    286 2020-12-03 09:10:52 UTC+0000
. 0xfffffa801ac4d060:RamCapture64.e                  4832   2460      6     70 2020-12-03 09:11:24 UTC+0000
. 0xfffffa80199e6a70:chrome.exe                      2904   2460     33   1694 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801ad9eb30:chrome.exe                     3328   2904     13    231 2020-12-03 09:10:33 UTC+0000
.. 0xfffffa801ae2e7d0:chrome.exe                     3456   2904     12    196 2020-12-03 09:10:42 UTC+0000
.. 0xfffffa801addfb30:chrome.exe                     3380   2904     13    304 2020-12-03 09:10:34 UTC+0000
.. 0xfffffa801ae269e0:chrome.exe                     3444   2904     13    231 2020-12-03 09:10:38 UTC+0000
.. 0xfffffa801ae63060:chrome.exe                     3568   2904     12    222 2020-12-03 09:10:44 UTC+0000
.. 0xfffffa801ad3ab30:chrome.exe                     3240   2904     13    218 2020-12-03 09:10:30 UTC+0000
.. 0xfffffa8019989b30:chrome.exe                     1628   2904      8    152 2020-12-03 09:10:21 UTC+0000
.. 0xfffffa801af63b30:chrome.exe                     3232   2904     12    182 2020-12-03 09:11:00 UTC+0000
.. 0xfffffa801afaf630:chrome.exe                     4268   2904     12    171 2020-12-03 09:11:04 UTC+0000
.. 0xfffffa801a91d630:chrome.exe                      692   2904     13    225 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801a84cb30:chrome.exe                     1340   2904     13    280 2020-12-03 09:10:24 UTC+0000
.. 0xfffffa801ad0eb30:chrome.exe                     3160   2904     15    286 2020-12-03 09:10:29 UTC+0000
.. 0xfffffa801acd1060:chrome.exe                     1648   2904     13    227 2020-12-03 09:10:28 UTC+0000
.. 0xfffffa801ad3cb30:chrome.exe                     3220   2904     15    295 2020-12-03 09:10:30 UTC+0000
.. 0xfffffa801998bb30:chrome.exe                     1392   2904     10    274 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801af22b30:chrome.exe                     1348   2904     12    171 2020-12-03 09:10:59 UTC+0000
.. 0xfffffa801a1d5b30:chrome.exe                      852   2904     10    170 2020-12-03 09:10:20 UTC+0000
.. 0xfffffa801afbeb30:chrome.exe                     4380   2904     12    179 2020-12-03 09:11:04 UTC+0000
.. 0xfffffa801acbeb30:chrome.exe                     1112   2904     14    251 2020-12-03 09:10:27 UTC+0000
.. 0xfffffa801aeb5b30:chrome.exe                     2492   2904     12    171 2020-12-03 09:10:58 UTC+0000
.. 0xfffffa801afa6b30:chrome.exe                     4324   2904     14    180 2020-12-03 09:11:04 UTC+0000
.. 0xfffffa801acd8b30:chrome.exe                      272   2904     14    239 2020-12-03 09:10:27 UTC+0000
.. 0xfffffa801af9d060:chrome.exe                     4192   2904     12    168 2020-12-03 09:11:02 UTC+0000
.. 0xfffffa801ae89b30:chrome.exe                     3584   2904      9    173 2020-12-03 09:10:45 UTC+0000
.. 0xfffffa801ad9ab30:chrome.exe                     3388   2904     13    283 2020-12-03 09:10:34 UTC+0000
.. 0xfffffa801acedb30:chrome.exe                     3092   2904     13    212 2020-12-03 09:10:28 UTC+0000
.. 0xfffffa801ad8d060:chrome.exe                     3320   2904     13    218 2020-12-03 09:10:32 UTC+0000
```

**During the competition** I focused on dumping `notepad.exe` and `RamCapture64.e`. However these were rabbit holes that lead to nowhere. There were too many strings in `notepad.exe` dump that I could not analyse it. 

**After the competition** I realised that there were `Volatility plugins` that could help to analyse the memory. As there were several `chrome.exe` application process, the history of the web application can be dumped. 

3. Download `chromehistory` volatility plugin using this [link](https://github.com/superponible/volatility-plugins)


```
python vol.py --plugins=/Users/jichngan/Downloads/volatility-plugins/ -f ~/Downloads/forensics-challenge-1.mem --profile=Win7SP1x64 chromehistory
```

> During testing, I realise that the downloaded plugins must be in the **same directory** as the memory file to work.

```
     8 http://www.mediafire.com/view/5wo9db2pa7gdcoc/This_is_a_png_file.png/file        This is a png file.png - MediaFire                                                    3     0 2020-12-03 09:10:50.055213        N/A       
    24 http://www.mediafire.com/view/5wo9db2pa7gdcoc/                                   This is a png file.png - MediaFire                                                    3     0 2020-12-03 08:24:50.579952        N/A     
```

These two lines of visited website seems very suspicious. Indeed, going to it, there will be a file to be downloaded

4. On download of the file, the file is noticed to be extremely small. Performing basic forensics such as `strings` on it yielded very little text. 

After staring at the picture, which consists of several different coloured boxes and a black bar, I thought of RGB encoding of the flag. 

Inputting the file into this [link](https://www.freefileconvert.com/image-converter) and converting `.png` to `.rgb` the flag can be found by `cat`-ing the RGB file!

Flag: `govtech-csg{m3m0ry_*************}`
> Full flag can be found by following above steps.

