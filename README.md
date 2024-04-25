Cuthulu Collection Tool
This IR collection script was made as part of a final project for a graduate class at George Mason University. It is written in PowerShell and will collect triage artifacts from a Windows endpoint, as well as memory. Memory is collected using DumpIt.
The script is self-contained, that is, there is no need to download additional files, so long as all of the files here are downloaded and saved to the same directory. Downloading this as a .zip file and running it is the best option. 

The Cthulu_Collection.exe and Cthulu_Collection.ps1 file do the same thing, just are called by different programs. The output is essentially hardcoded to C:\<currentuser>\Desktop\Cthulu. When running the program, there will be two messages boxes displayed
reminding the user where the output files are saved to.

To execute the collection tool, either double-click the .exe file or right-click on the .ps1, then select "run with PowerShell." If memory collection is desired, DumpIt will ask the user if they want to begin processing memory and if they want the memory file 
compressed. Simply enter 'y' for both and everything else will process. There will be a message at the end stating the collection is complete whenever the program is finished.

Way ahead:

Currently the .exe will open a command prompt window and display text. The program is working as intended, but the text in the command prompt could be interpreted things are not going as they should. The commmand prompt windows is going to be removed so that
is not seen in the future.

Potentially add in functionality for users to select their desired output directory 

Add in more robust collection

Create IR script for MAC and LINUX
