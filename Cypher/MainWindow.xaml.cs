using System;
using System.IO;
using System.Security.Cryptography;
using System.Windows;
using Microsoft.Win32;
using MahApps.Metro.Controls;
using System.Text.RegularExpressions;

namespace Cypher
{
    public partial class MainWindow : MetroWindow
    {
        private string SelectedFilePath;
        private byte[] fileContent;
        private string SelectedKeyIvFilePath;
        public MainWindow()
        {
            InitializeComponent();
            decryptPanel.Visibility = Visibility.Collapsed;
            homeButton.Visibility = Visibility.Collapsed;
        }
        private void OnBrowseButtonClicked(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "All Files (*.*)|*.*"
            };
            if (ofd.ShowDialog() == true)
            {
                SelectedFilePath = ofd.FileName;
                fileContent = File.ReadAllBytes(SelectedFilePath);
                long fileSizeInBytes = new FileInfo(SelectedFilePath).Length;
                string fileSizeString = GetReadableFileSize(fileSizeInBytes);
                fileNameTextBlock.Text = $"Selected file: {Path.GetFileName(SelectedFilePath)}";
                fileSizeTextBlock.Text = $"File size: {fileSizeString}";           
                fileInfoPanel.Visibility = Visibility.Visible;
                encrypt.Visibility = Visibility.Visible;
                decrypt.Visibility = Visibility.Visible;
                browse.Visibility = Visibility.Collapsed;
                homeButton.Visibility = Visibility.Visible;
                historyButton.Visibility = Visibility.Collapsed;
            }
        }


        private void OnEncryptButtonClicked(object sender, RoutedEventArgs e)
        {
            try
            {
                EncryptFile(SelectedFilePath, fileContent);
            }
            catch (Exception ex)
            {
                LogActivity("Encryption", SelectedFilePath, "N/A", fileContent.Length, false, ex.Message);
            }

            OnHomeButtonClicked(null, null);
        }


        private void OnDecryptButtonClicked(object sender, RoutedEventArgs e)
        {
            encrypt.Visibility = Visibility.Collapsed;
            decrypt.Visibility = Visibility.Collapsed;

            decryptPanel.Visibility = Visibility.Visible; 
            homeButton.Visibility = Visibility.Visible; 
            fileInfoPanel.Visibility = Visibility.Collapsed; 

        }

        private void OnSelectKeyIvButtonClicked(object sender, RoutedEventArgs e)
        {
            var ofd = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt|All Files (*.*)|*.*"
            };
            if (ofd.ShowDialog() == true)
            {
                SelectedKeyIvFilePath = ofd.FileName;
                ShowErrorMessage($"Selected Key/IV File: {SelectedKeyIvFilePath}");
            }
        }

        private void OnDecryptFileButtonClicked(object sender, RoutedEventArgs e)
        {
            string keyInput = keyText.Text;
            string ivInput = ivText.Text;
            string previousExtension = extensionText.Text;

            if (!string.IsNullOrEmpty(SelectedKeyIvFilePath) || (!string.IsNullOrEmpty(keyInput) && !string.IsNullOrEmpty(ivInput)))
            {
                try
                {
                    DecryptFile(SelectedFilePath, SelectedKeyIvFilePath, keyInput, ivInput, previousExtension);
                    OnHomeButtonClicked(null, null);
                }
                catch (FormatException ex)
                {
                    ShowErrorMessage($"Decryption failed: {ex.Message}");
                }
                catch (Exception ex)
                {
                    ShowErrorMessage($"An error occurred: {ex.Message}");
                }
            }
            else
            {
                ShowErrorMessage("Please select a Key/IV file or provide Key and IV values.");
            }
        }

        private void OnHomeButtonClicked(object sender, RoutedEventArgs e)
        {
            decryptPanel.Visibility = Visibility.Collapsed;
            browse.Visibility = Visibility.Visible;
            encrypt.Visibility = Visibility.Collapsed;
            decrypt.Visibility = Visibility.Collapsed;

            fileInfoPanel.Visibility = Visibility.Collapsed;

            keyText.Clear();
            ivText.Clear();
            extensionText.Clear();
            SelectedFilePath = null;
            SelectedKeyIvFilePath = null;
            fileContent = null;

            activityLogListView.ItemsSource = null;
            activityLogListView.Visibility = Visibility.Collapsed;
            historyButton.Visibility = Visibility.Visible;
            homeButton.Visibility = Visibility.Collapsed;
        }



        public void EncryptFile(string filePath, byte[] fileContent)
        {
            string directoryPath = "key_iv";
            if (!Directory.Exists(directoryPath))
            {
                Directory.CreateDirectory(directoryPath);
            }

            string keyIvFileName = Path.Combine(directoryPath, Path.GetFileNameWithoutExtension(filePath) + "_key_iv.txt");

            byte[] key = new byte[32];
            byte[] iv = new byte[16];
            RandomNumberGenerator.Fill(key);
            RandomNumberGenerator.Fill(iv);

            File.WriteAllText(keyIvFileName, $"{Convert.ToBase64String(key)}\n{Convert.ToBase64String(iv)}\nExtension: {Path.GetExtension(filePath)}");

            var sfd = new SaveFileDialog()
            {
                Filter = "Encrypted Files (*.enc)|*.enc"
            };

            if (sfd.ShowDialog() == true)
            {
                using (var encryptedStream = new FileStream(sfd.FileName, FileMode.Create))
                using (var cryptoStream = new CryptoStream(encryptedStream, Aes.Create().CreateEncryptor(key, iv), CryptoStreamMode.Write))
                {
                    cryptoStream.Write(fileContent, 0, fileContent.Length);
                }

                LogActivity("Encryption", filePath, sfd.FileName, fileContent.Length, true);
                ShowSuccessMessage($"File successfully encrypted and saved as:\n{sfd.FileName}");
            }
        }


        public void DecryptFile(string filePath, string keyIvFilePath, string keyInput, string ivInput, string previousExtension)
        {
            byte[] key = null;
            byte[] iv = null;

            if (!string.IsNullOrEmpty(keyIvFilePath) && File.Exists(keyIvFilePath))
            {
                var keyIvData = File.ReadAllLines(keyIvFilePath);
                if (keyIvData.Length < 3)
                {
                    ShowErrorMessage("Key/IV file format is invalid. Please check the file content.");
                }

                key = Convert.FromBase64String(keyIvData[0].Trim());
                iv = Convert.FromBase64String(keyIvData[1].Trim());
                previousExtension = keyIvData[2].Split(':')[1].Trim();
            }
            else if (!string.IsNullOrEmpty(keyInput) && !string.IsNullOrEmpty(ivInput))
            {
                key = Convert.FromBase64String(keyInput);
                iv = Convert.FromBase64String(ivInput);
            }
            else
            {
                ShowErrorMessage("Key and IV must be provided either through the Key/IV file or directly.");
            }

            long originalFileSize = new FileInfo(filePath).Length;

            using (var encryptedStream = new FileStream(filePath, FileMode.Open))
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;

                string decryptedFilePath = Path.Combine(Path.GetDirectoryName(filePath), Path.GetFileNameWithoutExtension(filePath) + previousExtension);

                using (var decryptedStream = new FileStream(decryptedFilePath, FileMode.Create))
                using (var cryptoStream = new CryptoStream(encryptedStream, aes.CreateDecryptor(), CryptoStreamMode.Read))
                {
                    cryptoStream.CopyTo(decryptedStream);
                }
            }

            LogActivity("Decryption", filePath, Path.GetFileNameWithoutExtension(filePath) + previousExtension, originalFileSize, true);
            ShowSuccessMessage($"File decrypted successfully: {Path.GetFileNameWithoutExtension(filePath) + previousExtension}");
        }

        private string FormatFileSize(long bytes)
        {
            if (bytes < 1024)
                return $"{bytes} B"; 
            else if (bytes < 1024 * 1024)
                return $"{Math.Round(bytes / 1024.0, 2)} KB";
            else if (bytes < 1024 * 1024 * 1024)
                return $"{Math.Round(bytes / (1024.0 * 1024.0), 2)} MB";
            else
                return $"{Math.Round(bytes / (1024.0 * 1024.0 * 1024.0), 2)} GB";
        }
        public void ShowSuccessMessage(string message)
        {
            CustomMessageBox customMessageBox = new CustomMessageBox(message);
            customMessageBox.ShowDialog();
        }
        public void ShowErrorMessage(string message)
        {
            var messageBox = new CustomMessageBox(message);
            messageBox.ShowDialog();
        }
        private string GetReadableFileSize(long bytes)
        {
            string[] units = { "B", "KB", "MB", "GB", "TB" };
            double size = bytes;
            int unitIndex = 0;

            while (size >= 1024 && unitIndex < units.Length - 1)
            {
                size /= 1024;
                unitIndex++;
            }

            return $"{size:0.##} {units[unitIndex]}";
        }
        private void LogActivity(string operationType, string filePath, string destinationPath, long fileSize, bool success, string errorMessage = null)
        {
            string formattedSize = GetReadableFileSize(fileSize);

            string logEntry = $"{DateTime.Now}: Operation: {operationType}, " +
                              $"Source: {filePath}, Destination: {destinationPath}, " +
                              $"Size: {formattedSize}, Success: {success}";

            if (!success && errorMessage != null)
            {
                logEntry += $", Error: {errorMessage}";
            }

            File.AppendAllText("activity_log.txt", logEntry + Environment.NewLine);
        }

        private void OnHistoryButtonClicked(object sender, RoutedEventArgs e)
        {
            LoadActivityLog();
        }
        public class LogEntry
        {
            public string OperationType { get; set; }
            public string FilePath { get; set; }
            public string DestinationPath { get; set; }
            public string FileSize { get; set; }
            public string Status { get; set; }
            public string ErrorMessage { get; set; }
        }
        private void LoadActivityLog()
        {
            string logFilePath = "activity_log.txt";
            if (File.Exists(logFilePath))
            {
                var logEntries = new List<LogEntry>();
                string pattern = @"(?<timestamp>[^:]+): Operation: (?<operation>[^,]+), Source: (?<source>[^,]+), Destination: (?<destination>[^,]+), Size: (?<size>[^,]+), Success: (?<success>.+)";

                foreach (var line in File.ReadLines(logFilePath))
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        continue;
                    }

                    try
                    {
                        var match = Regex.Match(line, pattern);
                        if (!match.Success)
                        {
                            MessageBox.Show($"Niepoprawny format linii: {line}");
                            continue;
                        }

                        logEntries.Add(new LogEntry
                        {
                            OperationType = match.Groups["operation"].Value,
                            FilePath = match.Groups["source"].Value,
                            DestinationPath = match.Groups["destination"].Value,
                            FileSize = match.Groups["size"].Value,
                            Status = match.Groups["success"].Value
                        });
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show($"Błąd odczytu linii: {line}\n{ex.Message}");
                        continue;
                    }
                }

                activityLogListView.ItemsSource = logEntries;
                activityLogListView.Visibility = Visibility.Visible;

                homeButton.Visibility = Visibility.Visible;
            }
            else
            {
                MessageBox.Show("Log file not found.");
            }
        }
    }
}
