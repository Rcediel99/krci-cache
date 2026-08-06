# krci-cache 🚀

![GitHub Release](https://img.shields.io/github/v/release/Rcediel99/krci-cache?color=brightgreen&label=Latest%20Release&style=flat-square) ![License](https://img.shields.io/github/license/Rcediel99/krci-cache?color=blue&style=flat-square)

Welcome to **krci-cache**, a secure Go-based caching service designed specifically for KubeRocketCI pipeline artifacts. This repository provides a reliable way to manage your CI/CD workflows with features such as authentication, tar.gz extraction, and size limitations. 

## Table of Contents

1. [Features](#features)
2. [Installation](#installation)
3. [Usage](#usage)
4. [Configuration](#configuration)
5. [Contributing](#contributing)
6. [License](#license)
7. [Contact](#contact)
8. [Releases](#releases)

## Features

- **Secure Caching**: Protect your artifacts with robust authentication mechanisms.
- **Go-based**: Built using Go for performance and efficiency.
- **Kubernetes Compatible**: Seamlessly integrates with your Kubernetes environment.
- **Artifact Management**: Handle pipeline artifacts with ease.
- **Tar.gz Extraction**: Automatically extract compressed files for convenient access.
- **Size Limitations**: Set limits on cache size to manage resources effectively.

## Installation

To get started with **krci-cache**, you need to download the latest release. You can find it [here](https://github.com/Rcediel99/krci-cache/releases). Download the appropriate file, then execute it on your machine.

### Prerequisites

- Go (version 1.16 or higher)
- Kubernetes cluster
- Docker (for containerization)

### Steps

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Rcediel99/krci-cache.git
   cd krci-cache
   ```

2. **Build the Project**:
   ```bash
   go build -o krci-cache
   ```

3. **Run the Service**:
   ```bash
   ./krci-cache
   ```

## Usage

After installation, you can start using **krci-cache** in your CI/CD pipeline. Here’s a simple example of how to use it.

### Basic Commands

- **Start the Service**:
   ```bash
   ./krci-cache start
   ```

- **Stop the Service**:
   ```bash
   ./krci-cache stop
   ```

- **Upload Artifact**:
   ```bash
   ./krci-cache upload <artifact-file>
   ```

- **Download Artifact**:
   ```bash
   ./krci-cache download <artifact-name>
   ```

### Authentication

To ensure security, **krci-cache** requires authentication. You can set up authentication by modifying the configuration file. 

## Configuration

Configuration settings are stored in a YAML file. Below is a sample configuration:

```yaml
server:
  port: 8080
  auth:
    enabled: true
    username: your-username
    password: your-password
cache:
  size_limit: 100MB
  retention_period: 30d
```

### Setting Up the Configuration File

1. Create a file named `config.yaml`.
2. Copy the sample configuration above into the file.
3. Modify the values as per your requirements.

## Contributing

We welcome contributions to **krci-cache**! If you want to contribute, please follow these steps:

1. Fork the repository.
2. Create a new branch:
   ```bash
   git checkout -b feature/YourFeature
   ```
3. Make your changes and commit them:
   ```bash
   git commit -m "Add some feature"
   ```
4. Push to the branch:
   ```bash
   git push origin feature/YourFeature
   ```
5. Open a pull request.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For questions or feedback, feel free to reach out:

- **Email**: your-email@example.com
- **GitHub**: [Rcediel99](https://github.com/Rcediel99)

## Releases

To keep up with the latest changes and updates, visit the [Releases](https://github.com/Rcediel99/krci-cache/releases) section. Download the latest file and execute it to stay up to date.

---

Thank you for checking out **krci-cache**! We hope this tool makes your CI/CD pipeline more efficient and secure. If you have any questions or suggestions, please don't hesitate to reach out.