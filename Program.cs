using System;
using System.Collections;
using System.Text;
using NBitcoin;
using System.IO;
using System.Security.Cryptography;
using static System.Console;

namespace Bitcoin_Wallet
{
    class BitcoinWallet
    {
        // Path where you want to store the Wallets
        const string walletFilePath = @"Wallets\";
        // BTC testnet derivation paths
        const string testNetBTCDerivationPath = "m/44'/1'/0'/0/";
        private static readonly Network currentNetwork = Network.TestNet;

        static void Main(string[] args)
        {
            string[] avaliableOperations =
            {
                //Allowed functionalities
                "create", "recover", "addresses", "exit"
            };
            string input = string.Empty;
            while (!input.ToLower().Equals("exit"))
            {
                do
                {
                    Write(
                        "Enter operation [\"Create\", \"Recover\", \"Addresses\", \"Exit\"]: ");
                    input = ReadLine().ToLower().Trim();
                } while (!((IList)avaliableOperations).Contains(input));

                switch (input)
                {
                    case "create":
                        CreateWallet();
                        break;
                    case "recover":
                        Write("Enter password: ");
                        string pw = ReadLine();
                        Write("Enter mnemonic phrase: ");
                        string mnemonic = ReadLine();
                        Write("Enter wallet's name: ");
                        string recoveredWalletName = ReadLine();
                        RecoverWallet(pw, mnemonic, recoveredWalletName);
                        break;
                    case "addresses":
                        Write("Enter wallet's name: ");
                        String walletName = ReadLine();
                        Write("Enter password: ");
                        pw = ReadLine();
                        Addresses(pw, walletName);
                        break;
                }
            }
        }

        private static void Addresses(string password, string walletName)
        {
            try
            {
                // TODO: Load the wallet and initialize variables
                string decryptedMnemonic = LoadAndDecrypt(password, walletName);
                Mnemonic mnemonic = new Mnemonic(decryptedMnemonic);
                ExtKey masterKey = mnemonic.DeriveExtKey();

                // TODO: Derive continuously and display the wallet address and private keys
                for (int i = 0; i < 10; i++)
                {
                    KeyPath keyPath = new KeyPath(testNetBTCDerivationPath + i);
                    ExtKey key = masterKey.Derive(keyPath);
                    WriteLine($"Address: {key.PrivateKey.PubKey.GetAddress(ScriptPubKeyType.Legacy, currentNetwork)} ->" +
                            $"Private key: {key.PrivateKey.GetBitcoinSecret(currentNetwork)} ");

                }
            }
            catch (Exception)
            {
                WriteLine("Wallet with such name does not exist!");

            }
        }

        private static void RecoverWallet(string password, string rawMnemonic, string walletName)
        {
            try
            {
                // TODO: Process the mnemonic string, encrypt it, and save to disk
                Mnemonic mnemonic = new Mnemonic(rawMnemonic);
                EncryptAndSave(mnemonic.ToString(), password, walletName);
                WriteLine("Wallet successfully recovered. Wallet name: " + walletName);
            }
            catch (Exception e)
            {
                WriteLine("An error occurred when recovering the wallet:" + e);
            }
        }

        private static void CreateWallet()
        {
            string pw;
            string pwConfirmed;

            do
            {
                Write("Enter password: ");
                pw = ReadLine();
                Write("Confirm password: ");
                pwConfirmed = ReadLine();
                if (pw != pwConfirmed)
                {
                    WriteLine("Passwords did not match!");
                    WriteLine("Try again.");
                }
            } while (pw != pwConfirmed);

            bool failure = true;
            while (failure)
            {
                try
                {
                    Write("Enter wallet name:");
                    string walletName = ReadLine();

                    // TODO: Create a new mnemonic
                    Mnemonic mnemonic = new Mnemonic(Wordlist.English, WordCount.Twelve);
                    ExtKey masterKey = mnemonic.DeriveExtKey();

                    WriteLine("Wallet created successfully");
                    WriteLine("Save or take note of the following mnemonic words.");
                    WriteLine();
                    WriteLine("----------");
                    WriteLine(mnemonic);
                    WriteLine("----------");
                    WriteLine(
                        "Keep your mnemonic secure. This is the only way that you can access your coins!");

                    // TODO: Derive the addresses and print the [derivation path, address -> private key] of each derivation
                    for (int i = 0; i < 10; i++)
                    {
                        KeyPath keyPath = new KeyPath(testNetBTCDerivationPath + i);
                        ExtKey key = masterKey.Derive(keyPath);
                        WriteLine($"DerivationPath: {keyPath} " +
                            $"Address: {key.PrivateKey.PubKey.GetAddress(currentNetwork)} -> " +
                            $"Private key: {key.PrivateKey.GetBitcoinSecret(currentNetwork)} ");
                    }

                    // TODO: Encrypt and save the mnemonic
                    EncryptAndSave(mnemonic.ToString(), pw, walletName);

                    failure = false;
                }
                catch (Exception e)
                {
                    WriteLine("Wallet already exists: " + e.Message);
                }
            }
        }

        // Preset AES-256-CBC Encryption Mechanism.

        public static string EncryptAndSave(string plainText, string keyString, string fileName)
        {
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] password = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(keyString));
            byte[] cipherData;
            Aes aes = Aes.Create();
            aes.Key = password;
            aes.GenerateIV();
            aes.Mode = CipherMode.CBC;
            ICryptoTransform cipher = aes.CreateEncryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream())
            {
                using (CryptoStream cs = new CryptoStream(ms, cipher, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(plainText);
                    }
                }
                cipherData = ms.ToArray();
            }

            byte[] combinedData = new byte[aes.IV.Length + cipherData.Length];
            Array.Copy(aes.IV, 0, combinedData, 0, aes.IV.Length);
            Array.Copy(cipherData, 0, combinedData, aes.IV.Length, cipherData.Length);
            string encryptedData = Convert.ToBase64String(combinedData);
            Save(encryptedData, fileName);
            return encryptedData;
        }

        public static void Save(string data, string fileName)
        {
            string fullPath = walletFilePath + fileName + ".wallet";
            if (File.Exists(fullPath))
                throw new NotSupportedException($"Wallet file already exists at {walletFilePath}");
            var directoryPath = Path.GetDirectoryName(Path.GetFullPath(walletFilePath));
            if (directoryPath != null) Directory.CreateDirectory(directoryPath);
            File.WriteAllText(fullPath, data);
        }

        public static string LoadAndDecrypt(string keyString, string fileName)
        {
            var rawContentString = File.ReadAllText(walletFilePath + fileName + ".wallet");
            string plainText;
            byte[] normalizedData = Convert.FromBase64String(rawContentString);
            SHA256 mySHA256 = SHA256Managed.Create();
            byte[] password = mySHA256.ComputeHash(Encoding.ASCII.GetBytes(keyString));
            Aes aes = Aes.Create();
            aes.Key = password;
            byte[] iv = new byte[aes.BlockSize / 8];
            byte[] cipherText = new byte[normalizedData.Length - iv.Length];
            Array.Copy(normalizedData, iv, iv.Length);
            Array.Copy(normalizedData, iv.Length, cipherText, 0, cipherText.Length);
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            ICryptoTransform decipher = aes.CreateDecryptor(aes.Key, aes.IV);

            using (MemoryStream ms = new MemoryStream(cipherText))
            {
                using (CryptoStream cs = new CryptoStream(ms, decipher, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        plainText = sr.ReadToEnd();
                    }
                }

                return plainText;
            }
        }
    }
}
