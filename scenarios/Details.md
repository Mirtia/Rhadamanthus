# Details

## Prerequisites (Preparation)

1. First, I created a VM and run the kernel debug script and install essentials script from the scripts folder:

```sh
# Install kernel debug symbols
sudo ./kernel_install_dbg.sh

# Install essential development tools
sudo ./scripts/install_essentials.sh --basics --net --bpf --uv --liburing --go --clang14
``` 

2. Then I copied the logical volume (created clones) so I could run the scenarios. Keep in mind to always keep a clean copy.

```sh
# Where if for input and of for output, check the checksums (optional)
# ea6e8a055094176948978b5a344f8a1c  /dev/vg/linux-test
# ea6e8a055094176948978b5a344f8a1c  /dev/vg/linux-placeholder
sudo dd if=/dev/vg/linux-test of=/dev/vg/linux-placeholder bs=4M status=progress
```

3. Now experiment!!