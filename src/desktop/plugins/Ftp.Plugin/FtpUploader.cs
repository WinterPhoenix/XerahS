#region License Information (GPL v3)

/*
    XerahS - The Avalonia UI implementation of ShareX
    Copyright (c) 2007-2026 ShareX Team

    This program is free software; you can redistribute it and/or
    modify it under the terms of the GNU General Public License
    as published by the Free Software Foundation; either version 2
    of the License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

    Optionally you can also view the license at <http://www.gnu.org/licenses/>.
*/

#endregion License Information (GPL v3)

using System.Collections.Generic;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using FluentFTP;
using FluentFTP.Exceptions;
using Renci.SshNet;
using Renci.SshNet.Common;
using XerahS.Common;
using XerahS.Uploaders;
using XerahS.Uploaders.FileUploaders;

namespace ShareX.Ftp.Plugin;

/// <summary>
/// File uploader for FTP, FTPS (FluentFTP), and SFTP (SSH.NET).
/// Uses FluentFTP for FTP/FTPS (modern, robust, SSL/TLS) and SSH.NET for SFTP.
/// </summary>
public sealed class FtpUploader : FileUploader, IDisposable
{
    private readonly FTPAccount _account;
    private FtpClient? _ftpClient;
    private SftpClient? _sftpClient;

    public FtpUploader(FTPAccount account)
    {
        _account = account ?? throw new ArgumentNullException(nameof(account));
    }

    public override UploadResult Upload(Stream stream, string fileName)
    {
        UploadResult result = new UploadResult();

        if (string.IsNullOrEmpty(_account.Host))
        {
            Errors.Add("FTP host is required.");
            return result;
        }

        // Use NameParserType.URL (not FilePath!) because FilePath calls
        // FileHelpers.SanitizePath which uses Windows' Path.GetPathRoot — that normalizes
        // a leading "/" into "\" on Windows, corrupting Unix-style SFTP remote paths
        // (e.g. "/var/www/share/" becomes "\var/www/share/"). The URL variant preserves
        // forward slashes as expected by FTP/SFTP servers.
        string subFolderPath = _account.GetSubFolderPath(null, NameParserType.URL);
        string remotePath = URLHelpers.CombineURL(subFolderPath, fileName);
        string url = _account.GetUriPath(fileName, subFolderPath);

        OnEarlyURLCopyRequested(url);

        try
        {
            IsUploading = true;

            bool ok = _account.Protocol switch
            {
                FTPProtocol.FTP or FTPProtocol.FTPS => UploadFtp(stream, remotePath),
                FTPProtocol.SFTP => UploadSftp(stream, remotePath),
                _ => false
            };

            if (ok && !StopUploadRequested && !IsError)
            {
                result.URL = url;
            }
        }
        finally
        {
            Dispose();
            IsUploading = false;
        }

        return result;
    }

    public override void StopUpload()
    {
        if (IsUploading && !StopUploadRequested)
        {
            StopUploadRequested = true;
            try
            {
                _ftpClient?.Disconnect();
                _sftpClient?.Disconnect();
            }
            catch (Exception ex)
            {
                DebugHelper.WriteException(ex);
            }
        }
    }

    private bool UploadFtp(Stream stream, string remotePath)
    {
        try
        {
            _ftpClient = CreateFtpClient();
            if (!ConnectFtp())
                return false;

            try
            {
                return UploadFtpInternal(stream, remotePath);
            }
            catch (FtpCommandException ex) when (ex.CompletionCode == "550" || ex.CompletionCode == "553")
            {
                CreateMultiDirectoryFtp(URLHelpers.GetDirectoryPath(remotePath));
                return UploadFtpInternal(stream, remotePath);
            }
        }
        catch (Exception ex)
        {
            Errors.Add(ex.Message);
            return false;
        }
    }

    private FtpClient CreateFtpClient()
    {
        var client = new FtpClient
        {
            Host = _account.Host,
            Port = _account.Port,
            Credentials = new NetworkCredential(_account.Username ?? "", _account.Password ?? "")
        };

        client.Config.DataConnectionType = _account.IsActive ? FtpDataConnectionType.AutoActive : FtpDataConnectionType.AutoPassive;

        if (_account.Protocol == FTPProtocol.FTPS)
        {
            client.Config.EncryptionMode = _account.FTPSEncryption == FTPSEncryption.Implicit ? FtpEncryptionMode.Implicit : FtpEncryptionMode.Explicit;
            client.Config.DataConnectionEncryption = true;
            client.ValidateCertificate += (_, e) =>
            {
                if (e.PolicyErrors != SslPolicyErrors.None)
                    e.Accept = true;
            };
        }

        return client;
    }

    private bool ConnectFtp()
    {
        if (_ftpClient == null) return false;
        if (!_ftpClient.IsConnected)
            _ftpClient.Connect();
        return _ftpClient.IsConnected;
    }

    private bool UploadFtpInternal(Stream stream, string remotePath)
    {
        if (_ftpClient == null || !_ftpClient.IsConnected) return false;
        using (Stream remoteStream = _ftpClient.OpenWrite(remotePath))
        {
            if (!TransferData(stream, remoteStream))
                return false;
        }
        return _ftpClient.GetReply().Success;
    }

    private void CreateMultiDirectoryFtp(string remotePath)
    {
        if (_ftpClient == null || string.IsNullOrEmpty(remotePath)) return;
        List<string> paths = URLHelpers.GetPaths(remotePath);
        foreach (string path in paths)
        {
            if (!string.IsNullOrEmpty(path) && !_ftpClient.DirectoryExists(path))
            {
                try { _ftpClient.CreateDirectory(path); } catch { /* ignore */ }
            }
        }
    }

    private bool UploadSftp(Stream stream, string remotePath)
    {
        try
        {
            _sftpClient = CreateSftpClient();
            if (!ConnectSftp())
                return false;

            try
            {
                return UploadSftpInternal(stream, remotePath);
            }
            catch (SftpPathNotFoundException)
            {
                CreateMultiDirectorySftp(URLHelpers.GetDirectoryPath(remotePath));
                return UploadSftpInternal(stream, remotePath);
            }
        }
        catch (Exception ex)
        {
            Errors.Add(ex.Message);
            return false;
        }
    }

    private SftpClient? CreateSftpClient()
    {
        if (!string.IsNullOrEmpty(_account.Keypath))
        {
            if (!File.Exists(_account.Keypath))
            {
                Errors.Add("SFTP key file not found: " + _account.Keypath);
                return null;
            }
            PrivateKeyFile keyFile = string.IsNullOrEmpty(_account.Passphrase)
                ? new PrivateKeyFile(_account.Keypath)
                : new PrivateKeyFile(_account.Keypath, _account.Passphrase);
            return new SftpClient(_account.Host, _account.Port, _account.Username ?? "", keyFile);
        }
        if (!string.IsNullOrEmpty(_account.Password))
            return new SftpClient(_account.Host, _account.Port, _account.Username ?? "", _account.Password);
        Errors.Add("SFTP requires either a key file or password.");
        return null;
    }

    private bool ConnectSftp()
    {
        if (_sftpClient == null) return false;
        if (!_sftpClient.IsConnected)
            _sftpClient.Connect();
        _sftpClient.BufferSize = (uint)BufferSize;
        return _sftpClient.IsConnected;
    }

    private bool UploadSftpInternal(Stream stream, string remotePath)
    {
        if (_sftpClient == null || !_sftpClient.IsConnected) return false;

        long fileSize = stream.CanSeek ? stream.Length : -1;
        ProgressManager? progress = fileSize > 0 ? new ProgressManager(fileSize) : null;
        ulong lastUploadedBytes = 0;
        ulong finalUploadedBytes = 0;
        object progressLock = new object();

        DebugHelper.WriteLine($"SFTP UploadFile begin: remotePath=\"{remotePath}\", fileSize={fileSize}, bufferSize={_sftpClient.BufferSize}.");
        var uploadStopwatch = System.Diagnostics.Stopwatch.StartNew();

        // We have to use a lock here because UploadFile fires progress callbacks concurrently from multiple threads.
        _sftpClient.UploadFile(stream, remotePath, canOverride: true, uploadedBytes =>
        {
            if (StopUploadRequested)
            {
                _sftpClient.Disconnect();
                return;
            }

            if (AllowReportProgress && progress != null)
            {
                lock (progressLock)
                {
                    long delta = (long)(uploadedBytes - lastUploadedBytes);

                    if (delta > 0)
                    {
                        lastUploadedBytes = uploadedBytes;
                        finalUploadedBytes = uploadedBytes;

                        if (progress.UpdateProgress(delta))
                        {
                            OnProgressChanged(progress);
                        }
                    }
                }
            }
            else
            {
                // Still track bytes when progress reporting is off.
                lock (progressLock)
                {
                    if (uploadedBytes > finalUploadedBytes)
                        finalUploadedBytes = uploadedBytes;
                }
            }
        });

        uploadStopwatch.Stop();
        DebugHelper.WriteLine($"SFTP UploadFile returned after {uploadStopwatch.ElapsedMilliseconds}ms, finalUploadedBytes={finalUploadedBytes}, expectedBytes={fileSize}, stopRequested={StopUploadRequested}.");

        if (StopUploadRequested) return false;

        // Post-upload verification: SSH.NET's UploadFile can silently return without throwing
        // even when the server didn't actually accept/persist the bytes. Verify by checking
        // the remote file's existence and size before declaring success.
        try
        {
            if (!_sftpClient.Exists(remotePath))
            {
                string msg = $"SFTP upload verification failed: remote file does not exist after upload ({remotePath}).";
                DebugHelper.WriteLine(msg);
                Errors.Add(msg);
                return false;
            }

            if (fileSize > 0)
            {
                var attrs = _sftpClient.GetAttributes(remotePath);
                if (attrs.Size != fileSize)
                {
                    string msg = $"SFTP upload verification failed: remote size {attrs.Size} != expected {fileSize} ({remotePath}).";
                    DebugHelper.WriteLine(msg);
                    Errors.Add(msg);
                    return false;
                }
            }

            DebugHelper.WriteLine($"SFTP upload verified: {remotePath} ({finalUploadedBytes} bytes transferred, remote size match).");
        }
        catch (Exception ex)
        {
            string msg = $"SFTP upload verification threw: {ex.Message}";
            DebugHelper.WriteLine(msg);
            Errors.Add(msg);
            return false;
        }

        return true;
    }

    private void CreateMultiDirectorySftp(string path)
    {
        if (_sftpClient == null || string.IsNullOrEmpty(path)) return;
        List<string> paths = URLHelpers.GetPaths(path);
        foreach (string dir in paths)
        {
            if (string.IsNullOrEmpty(dir)) continue;
            try
            {
                if (!_sftpClient.Exists(dir))
                    _sftpClient.CreateDirectory(dir);
            }
            catch (SftpPermissionDeniedException) { }
        }
    }

    public void Dispose()
    {
        try
        {
            _ftpClient?.Dispose();
            _ftpClient = null;
        }
        catch (Exception ex)
        {
            DebugHelper.WriteException(ex);
        }
        try
        {
            _sftpClient?.Dispose();
            _sftpClient = null;
        }
        catch (Exception ex)
        {
            DebugHelper.WriteException(ex);
        }
    }
}
