# C-manga-downloader
Subprocess for lmdx written in C for **blazingly fast** downloading of manga.  
very early in development  

# Requires
[nob.h](https://github.com/tsoding/nob.h)  
[arena.h](https://github.com/tsoding/arena)  
[stb_ds.h](https://github.com/nothings/stb)  
[stb_image.h](https://github.com/nothings/stb)  
[libwebp](https://github.com/webmproject/libwebp)  
[libcurl](https://curl.se/windows/)  


## Compilation
sidenote to myself because i had problem with libwebp compilation  
```bash
mkdir build
cd build
cmake -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release ..
```
