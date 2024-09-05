# Minimal Disassociation DoS Attack Detection

## Overview

This project introduces a novel **Discrete Event System (DES)-based Intrusion Detection System (IDS)** to detect **minimal disassociation Denial-of-Service (DoS) attacks** in Wi-Fi networks. Traditional attacks rely on flooding disassociation frames, but this minimal variant sends fewer frames, making detection challenging. Our IDS employs fictitious Stations (STAs) to effectively detect these low-rate attacks with high accuracy.

## How It Works

- **Fictitious STAs**: The IDS creates decoy stations that interact with the network but are programmed to never send disassociation frames. If the IDS detects disassociation frames associated with these fictitious STAs, it triggers an alert as it signifies an attack.
- **Spoofed Disassociation Detection**: Since disassociation frames are typically unencrypted in most Wi-Fi standards, they are vulnerable to spoofing. The IDS monitors network traffic and flags any spoofed disassociation frames targeted at fictitious STAs.
- **DES Model**: The system uses a DES model to represent the behavior of network states under normal and attack conditions, enabling precise detection of abnormal transitions caused by malicious disassociation attempts.

## Features

- **High Accuracy**: Achieves 100% accuracy when disassociation frames are captured.
- **Protocol-Agnostic**: Can be deployed on existing and future Wi-Fi networks without requiring protocol modifications.
- **Cost-Effective**: No need for hardware upgrades—works with standard Wi-Fi components and software.
- **Scalability**: Supports varying numbers of fictitious STAs to improve detection time, with optimal results at higher proportions of fictitious STAs.
