"""
=============================================================================
MODEL 1 — CLASSICAL CRYPTOGRAPHY
=============================================================================
Final Undergraduate Thesis: Data Protection with Quantum Cryptography
Author: Lucas Vieira
Centro Universitário Senac Santo Amaro — 2025

Description:
    This module implements a classical cryptography model to serve
    as a baseline for comparison with the quantum cryptography model.
    Two algorithms are implemented:
        - AES-256 (Symmetric Cryptography)
        - RSA-2048 (Asymmetric Cryptography)

    The goal is to collect performance metrics (execution time,
    error rate, throughput) for later comparison with the BB84
    protocol implemented via Qiskit.

Implemented functions (as per Table 3 of the thesis):
    - generate_message(n)
    - generate_key(n)
    - encrypt(message, key)
    - decrypt(ciphertext, key)
    - verify_integrity(original, recovered)
    - measure_time(func, *args)
    - collect_metrics()
    - generate_graphs(metrics)
=============================================================================
"""

import os
import time
import hashlib
import json
from datetime import datetime

# --- Symmetric Cryptography (AES-256-CBC) ---
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.backends import default_backend

# --- Asymmetric Cryptography (RSA-2048) ---
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives import hashes

# --- Visualization ---
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for saving figures
import matplotlib.pyplot as plt
import numpy as np


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def generate_message(n: int) -> bytes:
    """
    Generates a random message of n bytes.

    Parameters:
        n (int): Message size in bytes.

    Returns:
        bytes: Random sequence of n bytes.

    Example:
        >>> msg = generate_message(256)
        >>> len(msg)
        256
    """
    return os.urandom(n)


def measure_time(func, *args, **kwargs):
    """
    Measures the execution time of a function in milliseconds.

    Parameters:
        func: Function to be timed.
        *args: Positional arguments for the function.
        **kwargs: Keyword arguments for the function.

    Returns:
        tuple: (function_result, time_in_ms)
    """
    start = time.perf_counter()
    result = func(*args, **kwargs)
    end = time.perf_counter()
    time_ms = (end - start) * 1000  # Convert to milliseconds
    return result, time_ms


# =============================================================================
# SYMMETRIC CRYPTOGRAPHY — AES-256-CBC
# =============================================================================

class AESCipher:
    """
    Symmetric cryptography implementation using AES-256 in CBC mode.

    AES (Advanced Encryption Standard) is the modern standard for symmetric
    cryptography, replacing DES. It uses 128-bit blocks and keys of
    128, 192, or 256 bits. This implementation uses a 256-bit key
    (32 bytes) for maximum security.

    Attributes:
        name (str): Algorithm identifier.
        key_size (int): Key size in bytes (32 = 256 bits).
    """

    def __init__(self):
        self.name = "AES-256-CBC"
        self.key_size = 32  # 256 bits

    def generate_key(self, n: int = None) -> bytes:
        """
        Generates a random 256-bit symmetric key.

        Parameters:
            n (int): Ignored in this implementation (fixed key size of 32 bytes).

        Returns:
            bytes: 32-byte key (256 bits).
        """
        return os.urandom(self.key_size)

    def encrypt(self, message: bytes, key: bytes) -> dict:
        """
        Encrypts the message using AES-256-CBC.

        CBC (Cipher Block Chaining) mode uses a random 16-byte
        initialization vector (IV) to ensure that identical messages
        produce different ciphertexts.

        Parameters:
            message (bytes): Plaintext to be encrypted.
            key (bytes): 256-bit symmetric key.

        Returns:
            dict: {'iv': bytes, 'ciphertext': bytes}
        """
        # Generate random 128-bit IV (AES block size)
        iv = os.urandom(16)

        # Apply PKCS7 padding to align with block size (128 bits)
        padder = sym_padding.PKCS7(128).padder()
        padded_data = padder.update(message) + padder.finalize()

        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()

        return {'iv': iv, 'ciphertext': ciphertext}

    def decrypt(self, encrypted_data: dict, key: bytes) -> bytes:
        """
        Decrypts the ciphertext using AES-256-CBC.

        Parameters:
            encrypted_data (dict): Dictionary with 'iv' and 'ciphertext'.
            key (bytes): Same symmetric key used for encryption.

        Returns:
            bytes: Original plaintext.
        """
        iv = encrypted_data['iv']
        ciphertext = encrypted_data['ciphertext']

        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove padding
        unpadder = sym_padding.PKCS7(128).unpadder()
        message = unpadder.update(padded_data) + unpadder.finalize()

        return message


# =============================================================================
# ASYMMETRIC CRYPTOGRAPHY — RSA-2048
# =============================================================================

class RSACipher:
    """
    Asymmetric cryptography implementation using RSA-2048.

    RSA (Rivest-Shamir-Adleman) bases its security on the computational
    difficulty of factoring large integers. Shor's algorithm, run on a
    sufficiently powerful quantum computer, would be able to break this
    security in polynomial time.

    Note: RSA has a limitation on the message size it can directly encrypt.
    For larger messages, hybrid encryption (RSA + AES) is used, but here
    we implement pure RSA for comparison purposes.

    Attributes:
        name (str): Algorithm identifier.
        key_size (int): Key size in bits.
        private_key: RSA private key object.
        public_key: RSA public key object.
    """

    def __init__(self):
        self.name = "RSA-2048"
        self.key_size = 2048
        self.private_key = None
        self.public_key = None

    def generate_key(self, n: int = None) -> tuple:
        """
        Generates an RSA key pair (public and private).

        Parameters:
            n (int): Ignored (fixed size of 2048 bits).

        Returns:
            tuple: (private_key, public_key)
        """
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        return (self.private_key, self.public_key)

    def encrypt(self, message: bytes, public_key=None) -> bytes:
        """
        Encrypts the message using the RSA public key with OAEP padding.

        OAEP (Optimal Asymmetric Encryption Padding) is the recommended
        padding scheme for RSA, providing security against chosen-ciphertext
        attacks (CCA2).

        Limitation: RSA-2048 with OAEP-SHA256 can encrypt at most
        190 bytes per operation.

        Parameters:
            message (bytes): Plaintext (maximum ~190 bytes).
            public_key: RSA public key. If None, uses the generated one.

        Returns:
            bytes: Ciphertext.
        """
        if public_key is None:
            public_key = self.public_key

        ciphertext = public_key.encrypt(
            message,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes, private_key=None) -> bytes:
        """
        Decrypts the ciphertext using the RSA private key.

        Parameters:
            ciphertext (bytes): Data encrypted with the public key.
            private_key: RSA private key. If None, uses the generated one.

        Returns:
            bytes: Original plaintext.
        """
        if private_key is None:
            private_key = self.private_key

        message = private_key.decrypt(
            ciphertext,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return message


# =============================================================================
# INTEGRITY VERIFICATION
# =============================================================================

def verify_integrity(original: bytes, recovered: bytes) -> dict:
    """
    Verifies data integrity by comparing the original message
    with the message recovered after encryption and decryption.

    Uses SHA-256 hash for comparison and calculates the bit-level
    error rate when the data does not match.

    Parameters:
        original (bytes): Original message.
        recovered (bytes): Message recovered after decryption.

    Returns:
        dict: {
            'intact': bool,
            'hash_original': str,
            'hash_recovered': str,
            'error_rate': float (0.0 to 1.0),
            'differing_bits': int,
            'total_bits': int
        }
    """
    hash_original = hashlib.sha256(original).hexdigest()
    hash_recovered = hashlib.sha256(recovered).hexdigest()

    intact = (original == recovered)

    # Calculate bit-level error rate
    differing_bits = 0
    total_bits = max(len(original), len(recovered)) * 8

    min_size = min(len(original), len(recovered))
    for i in range(min_size):
        xor = original[i] ^ recovered[i]
        differing_bits += bin(xor).count('1')

    # Extra bits if sizes differ
    if len(original) != len(recovered):
        difference = abs(len(original) - len(recovered))
        differing_bits += difference * 8

    error_rate = differing_bits / total_bits if total_bits > 0 else 0.0

    return {
        'intact': intact,
        'hash_original': hash_original,
        'hash_recovered': hash_recovered,
        'error_rate': error_rate,
        'differing_bits': differing_bits,
        'total_bits': total_bits
    }


# =============================================================================
# METRICS COLLECTION
# =============================================================================

def collect_metrics(message_sizes: list = None, num_repetitions: int = 50) -> dict:
    """
    Runs systematic experiments and collects performance metrics
    for AES-256 and RSA-2048.

    For each message size, performs multiple repetitions and
    calculates mean and standard deviation of execution times.

    Parameters:
        message_sizes (list): List of sizes in bytes to test.
            Default: [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]
        num_repetitions (int): Number of repetitions per experiment.

    Returns:
        dict: Structured dictionary with all collected metrics.
    """
    if message_sizes is None:
        message_sizes = [16, 32, 64, 128, 256, 512, 1024, 2048, 4096]

    # RSA has a size limitation (~190 bytes with OAEP-SHA256)
    rsa_sizes = [s for s in message_sizes if s <= 190]

    metrics = {
        'timestamp': datetime.now().isoformat(),
        'num_repetitions': num_repetitions,
        'aes': {
            'sizes': message_sizes,
            'key_generation_time': [],
            'encryption_time': [],
            'decryption_time': [],
            'encryption_time_std': [],
            'decryption_time_std': [],
            'integrity': [],
            'encryption_throughput': [],  # bytes/second
        },
        'rsa': {
            'sizes': rsa_sizes,
            'key_generation_time': [],
            'encryption_time': [],
            'decryption_time': [],
            'encryption_time_std': [],
            'decryption_time_std': [],
            'integrity': [],
            'encryption_throughput': [],
        }
    }

    aes = AESCipher()
    rsa_crypto = RSACipher()

    print("=" * 70)
    print("METRICS COLLECTION — CLASSICAL CRYPTOGRAPHY")
    print("=" * 70)

    # -----------------------------------------------------------------
    # AES-256 Tests
    # -----------------------------------------------------------------
    print(f"\n{'='*70}")
    print(f"  AES-256-CBC | {num_repetitions} repetitions per size")
    print(f"{'='*70}")

    for size in message_sizes:
        encryption_times = []
        decryption_times = []
        errors = 0

        # Measure key generation once per size
        _, key_time = measure_time(aes.generate_key)

        for _ in range(num_repetitions):
            message = generate_message(size)
            key = aes.generate_key()

            # Encryption
            encrypted_data, t_encrypt = measure_time(aes.encrypt, message, key)
            encryption_times.append(t_encrypt)

            # Decryption
            recovered, t_decrypt = measure_time(aes.decrypt, encrypted_data, key)
            decryption_times.append(t_decrypt)

            # Verify integrity
            result = verify_integrity(message, recovered)
            if not result['intact']:
                errors += 1

        mean_encrypt = np.mean(encryption_times)
        mean_decrypt = np.mean(decryption_times)
        std_encrypt = np.std(encryption_times)
        std_decrypt = np.std(decryption_times)
        throughput = (size / (mean_encrypt / 1000)) if mean_encrypt > 0 else 0

        metrics['aes']['key_generation_time'].append(key_time)
        metrics['aes']['encryption_time'].append(mean_encrypt)
        metrics['aes']['decryption_time'].append(mean_decrypt)
        metrics['aes']['encryption_time_std'].append(std_encrypt)
        metrics['aes']['decryption_time_std'].append(std_decrypt)
        metrics['aes']['integrity'].append(1.0 - (errors / num_repetitions))
        metrics['aes']['encryption_throughput'].append(throughput)

        print(f"  [{size:>5} bytes] Encrypt: {mean_encrypt:.4f}ms (±{std_encrypt:.4f}) | "
              f"Decrypt: {mean_decrypt:.4f}ms (±{std_decrypt:.4f}) | "
              f"Integrity: {100*(1 - errors/num_repetitions):.1f}%")

    # -----------------------------------------------------------------
    # RSA-2048 Tests
    # -----------------------------------------------------------------
    print(f"\n{'='*70}")
    print(f"  RSA-2048 | {num_repetitions} repetitions per size")
    print("  (Maximum size: 190 bytes with OAEP-SHA256)")
    print(f"{'='*70}")

    for size in rsa_sizes:
        encryption_times = []
        decryption_times = []
        errors = 0

        # Measure key pair generation
        _, key_time = measure_time(rsa_crypto.generate_key)

        for _ in range(num_repetitions):
            rsa_crypto.generate_key()
            message = generate_message(size)

            # Encryption
            ciphertext, t_encrypt = measure_time(
                rsa_crypto.encrypt, message
            )
            encryption_times.append(t_encrypt)

            # Decryption
            recovered, t_decrypt = measure_time(
                rsa_crypto.decrypt, ciphertext
            )
            decryption_times.append(t_decrypt)

            # Verify integrity
            result = verify_integrity(message, recovered)
            if not result['intact']:
                errors += 1

        mean_encrypt = np.mean(encryption_times)
        mean_decrypt = np.mean(decryption_times)
        std_encrypt = np.std(encryption_times)
        std_decrypt = np.std(decryption_times)
        throughput = (size / (mean_encrypt / 1000)) if mean_encrypt > 0 else 0

        metrics['rsa']['key_generation_time'].append(key_time)
        metrics['rsa']['encryption_time'].append(mean_encrypt)
        metrics['rsa']['decryption_time'].append(mean_decrypt)
        metrics['rsa']['encryption_time_std'].append(std_encrypt)
        metrics['rsa']['decryption_time_std'].append(std_decrypt)
        metrics['rsa']['integrity'].append(1.0 - (errors / num_repetitions))
        metrics['rsa']['encryption_throughput'].append(throughput)

        print(f"  [{size:>5} bytes] Encrypt: {mean_encrypt:.4f}ms (±{std_encrypt:.4f}) | "
              f"Decrypt: {mean_decrypt:.4f}ms (±{std_decrypt:.4f}) | "
              f"Integrity: {100*(1 - errors/num_repetitions):.1f}%")

    # -----------------------------------------------------------------
    # Key Generation Comparison
    # -----------------------------------------------------------------
    print(f"\n{'='*70}")
    print("  COMPARISON: KEY GENERATION")
    print(f"{'='*70}")

    aes_keygen_times = []
    rsa_keygen_times = []

    for _ in range(num_repetitions):
        _, t = measure_time(aes.generate_key)
        aes_keygen_times.append(t)
        _, t = measure_time(rsa_crypto.generate_key)
        rsa_keygen_times.append(t)

    metrics['keygen_comparison'] = {
        'aes_mean': np.mean(aes_keygen_times),
        'aes_std': np.std(aes_keygen_times),
        'rsa_mean': np.mean(rsa_keygen_times),
        'rsa_std': np.std(rsa_keygen_times),
    }

    print(f"  AES-256:  {metrics['keygen_comparison']['aes_mean']:.4f}ms "
          f"(±{metrics['keygen_comparison']['aes_std']:.4f})")
    print(f"  RSA-2048: {metrics['keygen_comparison']['rsa_mean']:.4f}ms "
          f"(±{metrics['keygen_comparison']['rsa_std']:.4f})")
    print(f"  RSA/AES:  {metrics['keygen_comparison']['rsa_mean']/max(metrics['keygen_comparison']['aes_mean'], 0.0001):.1f}x slower")

    return metrics


# =============================================================================
# GRAPH GENERATION
# =============================================================================

def generate_graphs(metrics: dict, output_dir: str = "."):
    """
    Generates comparative graphs from the collected metrics.

    Graphs generated:
        1. Encryption time AES vs RSA
        2. Decryption time AES vs RSA
        3. Encryption throughput
        4. Key generation comparison

    Parameters:
        metrics (dict): Dictionary returned by collect_metrics().
        output_dir (str): Directory to save the images.
    """
    plt.style.use('seaborn-v0_8-whitegrid')

    # Consistent colors
    color_aes = '#2196F3'   # Blue
    color_rsa = '#FF5722'   # Orange/Red
    xlabel_size = 'Message Size (bytes)'

    # -----------------------------------------------------------------
    # Graph 1: Encryption Time
    # -----------------------------------------------------------------
    _, ax = plt.subplots(figsize=(10, 6))

    aes_sizes = metrics['aes']['sizes']
    rsa_sizes = metrics['rsa']['sizes']

    ax.errorbar(aes_sizes, metrics['aes']['encryption_time'],
                yerr=metrics['aes']['encryption_time_std'],
                marker='o', color=color_aes, linewidth=2, markersize=8,
                label='AES-256-CBC', capsize=4)

    ax.errorbar(rsa_sizes, metrics['rsa']['encryption_time'],
                yerr=metrics['rsa']['encryption_time_std'],
                marker='s', color=color_rsa, linewidth=2, markersize=8,
                label='RSA-2048', capsize=4)

    ax.set_xlabel(xlabel_size, fontsize=12)
    ax.set_ylabel('Encryption Time (ms)', fontsize=12)
    ax.set_title('Encryption Time Comparison: AES-256 vs RSA-2048', fontsize=14)
    ax.legend(fontsize=11)
    ax.set_xscale('log', base=2)
    ax.set_xticks(aes_sizes)
    ax.set_xticklabels([str(s) for s in aes_sizes])
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/graph_encryption_time.png', dpi=150)
    plt.close()

    # -----------------------------------------------------------------
    # Graph 2: Decryption Time
    # -----------------------------------------------------------------
    _, ax = plt.subplots(figsize=(10, 6))

    ax.errorbar(aes_sizes, metrics['aes']['decryption_time'],
                yerr=metrics['aes']['decryption_time_std'],
                marker='o', color=color_aes, linewidth=2, markersize=8,
                label='AES-256-CBC', capsize=4)

    ax.errorbar(rsa_sizes, metrics['rsa']['decryption_time'],
                yerr=metrics['rsa']['decryption_time_std'],
                marker='s', color=color_rsa, linewidth=2, markersize=8,
                label='RSA-2048', capsize=4)

    ax.set_xlabel(xlabel_size, fontsize=12)
    ax.set_ylabel('Decryption Time (ms)', fontsize=12)
    ax.set_title('Decryption Time Comparison: AES-256 vs RSA-2048', fontsize=14)
    ax.legend(fontsize=11)
    ax.set_xscale('log', base=2)
    ax.set_xticks(aes_sizes)
    ax.set_xticklabels([str(s) for s in aes_sizes])
    ax.grid(True, alpha=0.3)

    plt.tight_layout()
    plt.savefig(f'{output_dir}/graph_decryption_time.png', dpi=150)
    plt.close()

    # -----------------------------------------------------------------
    # Graph 3: Throughput
    # -----------------------------------------------------------------
    _, ax = plt.subplots(figsize=(10, 6))

    ax.bar([str(s) for s in aes_sizes],
           [tp / 1000 for tp in metrics['aes']['encryption_throughput']],
           color=color_aes, alpha=0.8, label='AES-256-CBC', width=0.35)

    ax.set_xlabel(xlabel_size, fontsize=12)
    ax.set_ylabel('Throughput (KB/s)', fontsize=12)
    ax.set_title('Encryption Throughput: AES-256', fontsize=14)
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3, axis='y')

    plt.tight_layout()
    plt.savefig(f'{output_dir}/graph_throughput.png', dpi=150)
    plt.close()

    # -----------------------------------------------------------------
    # Graph 4: Key Generation Comparison
    # -----------------------------------------------------------------
    _, ax = plt.subplots(figsize=(9, 6))

    keygen = metrics['keygen_comparison']
    algorithms_labels = ['AES-256\n(Symmetric)', 'RSA-2048\n(Asymmetric)']
    times = [keygen['aes_mean'], keygen['rsa_mean']]
    errors = [keygen['aes_std'], keygen['rsa_std']]
    colors = [color_aes, color_rsa]

    bars = ax.bar(algorithms_labels, times, yerr=errors, color=colors,
                  alpha=0.85, width=0.5, capsize=8,
                  edgecolor='white', linewidth=1.5,
                  error_kw={'elinewidth': 1.5, 'ecolor': 'black'})

    # Logarithmic scale so both bars are visible
    ax.set_yscale('log')

    # Labels with mean time above each bar
    for bar, t, err in zip(bars, times, errors):
        x = bar.get_x() + bar.get_width() / 2.
        ax.text(x, t + err * 1.5, f'{t:.4f} ms',
                ha='center', va='bottom', fontsize=11, fontweight='bold')

    # Annotation highlighting the speed ratio
    ratio = keygen['rsa_mean'] / keygen['aes_mean']
    ax.annotate(f'RSA is {ratio:,.0f}× slower\nthan AES in key generation',
                xy=(1, keygen['rsa_mean']), xytext=(0.5, keygen['rsa_mean'] * 0.05),
                fontsize=11, ha='center', color='#333333',
                bbox={'boxstyle': 'round,pad=0.4', 'facecolor': '#FFF9C4',
                      'edgecolor': '#FBC02D', 'alpha': 0.9},
                arrowprops={'arrowstyle': '->', 'color': '#333333', 'lw': 1.5})

    ax.set_ylabel('Generation Time (ms) — logarithmic scale', fontsize=12)
    ax.set_title('Comparison: Key Generation Time', fontsize=14)
    ax.grid(True, alpha=0.3, axis='y', which='both')

    def format_y_axis(val, _):
        if val < 0.01:
            return f'{val:.4f}'
        if val < 0.1:
            return f'{val:.3f}'
        if val < 10:
            return f'{val:.1f}'
        return f'{val:.0f}'

    ax.yaxis.set_major_formatter(plt.FuncFormatter(format_y_axis))

    plt.tight_layout()
    plt.savefig(f'{output_dir}/graph_key_generation.png', dpi=150)
    plt.close()

    print(f"\n  Graphs saved to: {output_dir}/")
    print("    - graph_encryption_time.png")
    print("    - graph_decryption_time.png")
    print("    - graph_throughput.png")
    print("    - graph_key_generation.png")


# =============================================================================
# MAIN EXECUTION
# =============================================================================

if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("  THESIS — DATA PROTECTION WITH QUANTUM CRYPTOGRAPHY")
    print("  Model 1: Classical Cryptography (AES-256 and RSA-2048)")
    print("  Author: Lucas Vieira")
    print("=" * 70)

    # Output directory
    output_dir = "results_classic"
    os.makedirs(output_dir, exist_ok=True)

    # Collect metrics
    metrics = collect_metrics(num_repetitions=50)

    # Generate graphs
    generate_graphs(metrics, output_dir=output_dir)

    # Save metrics to JSON for later use in comparison
    metrics_json = {
        'timestamp': metrics['timestamp'],
        'num_repetitions': metrics['num_repetitions'],
        'aes': {
            'sizes': metrics['aes']['sizes'],
            'encryption_time': metrics['aes']['encryption_time'],
            'decryption_time': metrics['aes']['decryption_time'],
            'integrity': metrics['aes']['integrity'],
            'encryption_throughput': metrics['aes']['encryption_throughput'],
        },
        'rsa': {
            'sizes': metrics['rsa']['sizes'],
            'encryption_time': metrics['rsa']['encryption_time'],
            'decryption_time': metrics['rsa']['decryption_time'],
            'integrity': metrics['rsa']['integrity'],
            'encryption_throughput': metrics['rsa']['encryption_throughput'],
        },
        'keygen_comparison': metrics['keygen_comparison']
    }

    with open(f'{output_dir}/metrics_classic.json', 'w') as f:
        json.dump(metrics_json, f, indent=2)

    print(f"\n  Metrics saved to: {output_dir}/metrics_classic.json")
    print("\n" + "=" * 70)
    print("  EXECUTION COMPLETE")
    print("=" * 70)
