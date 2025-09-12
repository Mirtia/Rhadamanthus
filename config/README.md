# Configuration

## libvmi.conf

It is required to create a profile for your VM and append it to the LibVMI configuration file. You can see full intrusctions on [LibVMI Installation Instructions](https://libvmi.com/docs/gcode-install.html). An example config (the one I used in my experiments) is listed as `libvmi.conf`.

## settings_schema.yaml

This is a placeholder file for the input configuration file needed to run the *VMI-Introspector* tool. You can comment out any event, interrupt or state tasks that you do not wish to monitor and easily modify the introspection window.

## Doxyfile

The configuration file used for the Doxygen documentation generation.