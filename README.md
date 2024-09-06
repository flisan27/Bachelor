# Bachelor Thesis Project Repository

### Contents:

Python_Scripts/: Python scripts developed for various analyses and computations in the project.

XML_Simulations/: XML files used for simulations in the CORE Network Emulator.

### Purpose:

This repository consolidates all the key components of my bachelor thesis project, including source code, and simulation files.

### Usage:

Python scripts can be run to replicate or analyze the study's findings.
XML files are for simulation setups in CORE Network Emulator.
Contributing:
For suggestions or issues, please open an issue in the repository.

### Instructions:

1. Start by downloading and installing Core Network Emulator for linux. See https://coreemu.github.io/core/install_ubuntu.html for installation guide.
2. Run the commands ```sudo core-daemon``` and ```core-gui``` in separate terminals to start the GUI
3. Now you have the ability to open run our scenarios from XML_Simulations/ or create your own!

### Tips for simulations

If you want to use Wireshark-GUI on the simulated machines to analyze traffic, open a terminal and enter the command ```xhost +``` to disable access control, meaning any application running on any machine can access and control the graphical display of the local machine. You can then open a GUI with Wireshark by typing ```DISPLAY=:0 wireshark``` on the node console.
 
We frequently used debug commands in OSPF such as ```debug ospf event``` and ```debug ospf packet (packet type)```. You can use ```show debugging ospf``` to confirm that they are on.



