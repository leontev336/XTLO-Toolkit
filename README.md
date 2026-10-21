# XTLO-Toolkit
Tools to help convert XTLO-formatted files to CSV and then repackage them back. 

XTLO refers to the header of some files used in games on the Xbox 360. This tool has been created to read, exctract, convert and repackage XTLO-formatted files.

The tool has been created to edit .loc files in the videogame Project Gotham Racing 4, as I am not aware of any other games that use XTLO files. They might not work on others, though you are free to try.

Required libraries: pandas, tqdm.

## Usage
To edit in-game strings:

1. Place the script in the same folder as your .loc files,
2. Open terminal (or cmd for Windows) in that folder,
3. Type `python unpacker_release.py` or `python3 unpacker_release.py`,
4. Wait for the script to finish,
5. Open the newly created csv file in your editor of choice, make sure you're only editing the "Edit_here" column of the file,
6. Type `python unpacker_release.py` or `python3 unpacker_release.py` in the same terminal/cmd window,
7. Wait for the script to finish.

*AI USAGE DISCLOSURE: I have only used AI to research the portion of internal hash tables.*
