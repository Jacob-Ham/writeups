# Corrupted
1. We are given a Corrupted.001 file, researching the file type, we learn 7-Zip should be able to extract the contents

```bash
sudo apt install p7zip-full
```

2. lets dump the contents

```bash
7z e Corrupted.001
```

3. We are given multiple image files and some system files, opening the images and looking at them the flag is hidden with dark text within the Capture (1).png file

## Flag ##
**crew{34sY_C0rrupt3D_GPT}**
