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


click on create credentials

copy  the configuration information go back to your terminal and paste it 
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

Now that we've set up ClearML, all that's left is to set up our listener, edit the exploit file to include our IP and port number, and then run the exploit.

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


i'm not going to explain fully the contents of /models/evaluate_model.py

But it is used to load and evaluate a PyTorch model, specifically a CustomCNN (convolutional neural network model with two convolutional layers followed by fully connected layers.)

then the `load_model(model_path)` function loads the model’s state dictionary from the specified file path and prepares it for evaluation.
this is where our payload will be fed

after trying a couple of exploits 

