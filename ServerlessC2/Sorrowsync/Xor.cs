using Microsoft.WindowsAzure.Storage.Blob;
using System;
using System.IO;
using System.IO.Compression;
using System.Text;
using System.Threading.Tasks;

public static class Xor
{
    public static byte[] XorEncryptDecrypt(byte[] input, string key)
    {
        byte[] output = new byte[input.Length];
        for (int i = 0; i < input.Length; i++)
        {
            output[i] = (byte)(input[i] ^ key[i % key.Length]);
        }
        return output;
    }

    public static byte[] Decompress(byte[] data)
    {
        using (var compressedStream = new MemoryStream(data))
        using (var zipStream = new GZipStream(compressedStream, CompressionMode.Decompress))
        using (var resultStream = new MemoryStream())
        {
            zipStream.CopyTo(resultStream);
            return resultStream.ToArray();
        }
    }

    public static byte[] Compress(byte[] data)
    {
        using (var compressedStream = new MemoryStream())
        using (var zipStream = new GZipStream(compressedStream, CompressionMode.Compress))
        {
            zipStream.Write(data, 0, data.Length);
            zipStream.Close();
            return compressedStream.ToArray();
        }
    }

    public static async Task EncryptAndUploadFile(string filePath, string xorKey, CloudBlobContainer container)
    {
        // Read the file
        byte[] fileBytes = await File.ReadAllBytesAsync(filePath);

        // Encrypt the file data
        byte[] encryptedBytes = XorEncryptDecrypt(fileBytes, xorKey);

        // Convert to Base64
        string base64Encrypted = Convert.ToBase64String(encryptedBytes);

        // Save to Blob Storage (or local `/vault/` directory)
        string blobName = Path.GetFileName(filePath) + ".enc";
        CloudBlockBlob blob = container.GetBlockBlobReference(blobName);
        await blob.UploadTextAsync(base64Encrypted);
    }

    public static async Task DecryptAndDownloadFile(string blobName, string xorKey, CloudBlobContainer container)
    {
        CloudBlockBlob blob = container.GetBlockBlobReference(blobName);
        string base64Encrypted = await blob.DownloadTextAsync();

        // Convert from Base64 and decrypt
        byte[] encryptedBytes = Convert.FromBase64String(base64Encrypted);
        byte[] decryptedBytes = XorEncryptDecrypt(encryptedBytes, xorKey);

        // Define the path where the decrypted file will be saved
        string decryptedFilePath = Path.Combine(Path.GetTempPath(), blobName.Replace(".xor", ""));

        // Save the decrypted data back to a file
        await File.WriteAllBytesAsync(decryptedFilePath, decryptedBytes);
    }


    /*    public static async Task EncryptAndUploadFile(string filePath, string xorKey, CloudBlobContainer container)
        {
            // Read the file
            byte[] fileBytes = await File.ReadAllBytesAsync(filePath);
            // Compress it
            byte[] compressedBytes = Compress(fileBytes);
            // Encrypt the compressed data
            byte[] encryptedBytes = XorEncryptDecrypt(compressedBytes, xorKey);
            // Convert to Base64
            string base64Encrypted = Convert.ToBase64String(encryptedBytes);

            // Save to Blob Storage (or local `/vault/` directory)
            string blobName = Path.GetFileName(filePath) + ".enc";
            CloudBlockBlob blob = container.GetBlockBlobReference(blobName);
            await blob.UploadTextAsync(base64Encrypted);
        }

        public static async Task DecryptAndDownloadFile(string blobName, string xorKey, CloudBlobContainer container)
        {
            CloudBlockBlob blob = container.GetBlockBlobReference(blobName);
            string base64Encrypted = await blob.DownloadTextAsync();

            // Convert from Base64 and decrypt
            byte[] encryptedBytes = Convert.FromBase64String(base64Encrypted);
            byte[] decryptedBytes = XorEncryptDecrypt(encryptedBytes, xorKey);

            // Decompress
            byte[] decompressedBytes = Decompress(decryptedBytes);

            // Define the path where the decrypted file will be saved
            string decryptedFilePath = Path.Combine(Path.GetTempPath(), blobName.Replace(".enc", ""));

            // Save the decrypted, decompressed data back to a file
            await File.WriteAllBytesAsync(decryptedFilePath, decompressedBytes);
        }*/
}
