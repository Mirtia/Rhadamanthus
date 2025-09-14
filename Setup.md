

## Virtual Machine Management

### Storage Setup

The project uses LVM (Logical Volume Manager) for storage management:

```sh
# Create logical volumes for VMs
sudo lvcreate -L 20G -n ubuntu-20-04-new-kernel vg0

# Example of attaching volume at running VM, it should not be currently mounted.
sudo xl block-attach ubuntu-20-04-new-kernel  phy:/dev/vg/file-transfer xvdb w
```

**Note**: I tried taking snapshots using *lv*, but since I wasn't very familiar with it, I ended up having merging issues when I wanted to restore a disk state. In the end, I chose *dd* for cloning.

## Workspace

I first added a basic firewall (*ufw*) and only allowed an open port for *ssh* connections.
Then, since I am using VNC for the display of the domU VMs, I decided to use [noVNC](https://novnc.com/).

This is what I typically run:
```sh
# 5900 is the port of VNC, 6081 is an arbirtrary port I chose to proxy
./noVNC/utils/novnc_proxy --vnc localhost:5900 --listen localhost:6081
# I then tunnel the connection through ssh so that I can access the view through my browser.
ssh nootkit@debian -i ~/.ssh/id_nootkit -L 6081:localhost:6081
# Finally visiting the browser, http://localhost:6081/vnc.html?host=localhost&port=6081.
```

- **xl console**: I will write more on the scripts necessary for running with tty. Both guest and host need some configuration.

**Note**: Some hardware (like EliteBooks ugh...) have limited driver support with Debian, and after Xen installation, everything just goes downhill, making SSH the preferred access method. For example, in my case, the Elitebook touchpad stopped working.
