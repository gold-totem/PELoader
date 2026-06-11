# PE Loader

A PE loader implementation that demonstrates manual PE mapping.

## Features

- Supports loading 32-bit PE images into 32-bit processes.
- Supports loading 64-bit PE images into 64-bit processes.
- Supports invoking an executable's entry point after a successful load.
- Supports invoking an exported function when the image is loaded into a remote process.
- For local loading scenarios, supports execution of:
  - DLL entry points (`DllMain`)
  - Thread Local Storage (TLS) callbacks

## Requirements

- Windows
- Visual Studio 2026

## Building

### 1. Clone the Repository

```cmd
git clone https://github.com/gold-totem/PELoader.git
cd PEloader
```

### 2. Build Using MSBuild

Open a Visual Studio Developer Command Prompt and run:

```cmd
msbuild PELoader.slnx /p:Configuration=Release /p:Platform=x64
```