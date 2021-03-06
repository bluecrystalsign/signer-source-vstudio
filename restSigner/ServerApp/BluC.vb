﻿
'    Blue Crystal: Document Digital Signature Tool
'   Copyright (C) 2007-2015  Sergio Leal
'    This program is free software: you can redistribute it and/or modify
'    it under the terms of the GNU Affero General Public License as
'    published by the Free Software Foundation, either version 3 of the
'    License, or (at your option) any later version.
'    This program is distributed in the hope that it will be useful,
'    but WITHOUT ANY WARRANTY; without even the implied warranty of
'    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
'    GNU Affero General Public License for more details.
'    You should have received a copy of the GNU Affero General Public License
'    along with this program.  If not, see <http://www.gnu.org/licenses/>.

Imports System
Imports System.Security.Cryptography
Imports System.Security.Permissions
Imports System.IO
Imports System.Security.Cryptography.X509Certificates

Imports System.Text.RegularExpressions
Imports System.Security.Cryptography.Pkcs



Module BluC
    Private certificate As X509Certificate2
    Private signer As ittru.signAx = New ittru.signAx

    Public Function getCertificate(title As String, message As String, subjectRegex As String, issuerRegex As String) As String
        Dim certTorRet As String = signer.getCertificate(title, message, subjectRegex, issuerRegex)
        Return certTorRet
    End Function

    Public Function getSubject() As String
        Return signer.getSubject
    End Function
    Public Function debugInfo() As DebugInfo
        'Public subject As String
        'Public issuer As String
        'Public notBefore As DateTime
        'Public notAfter As DateTime
        'Public keyUsageDS As Boolean
        'Public keyUsageNR As Boolean
        'Public isPrivate As Boolean
        Dim ret As DebugInfo = New DebugInfo

        Dim store As New X509Store(StoreName.My)
        store.Open(OpenFlags.OpenExistingOnly)
        Dim certificates As X509Certificate2Collection = store.Certificates
        For Each nextCert As X509Certificate2 In certificates
            Dim nextDbgInfo As DbgAppCerts = New DbgAppCerts
            nextDbgInfo.subject = nextCert.SubjectName.Name
            nextDbgInfo.issuer = nextCert.IssuerName.Name
            nextDbgInfo.notBefore = nextCert.NotBefore.ToString("dd/MM/yyyy H:mm:ss zzz")
            nextDbgInfo.notAfter = nextCert.NotAfter.ToString("dd/MM/yyyy H:mm:ss zzz")

            Dim exts As X509ExtensionCollection = nextCert.Extensions
            For Each nextExt As X509Extension In exts
                If (nextExt.Oid.Value = "2.5.29.15") Then
                    Dim kuExt As X509KeyUsageExtension = DirectCast(nextExt, X509KeyUsageExtension)
                    Dim kuFlags As X509KeyUsageFlags = kuExt.KeyUsages
                    If ((kuFlags And X509KeyUsageFlags.DigitalSignature) <> X509KeyUsageFlags.None) Then
                        nextDbgInfo.keyUsageDS = True
                    End If
                    If ((kuFlags And X509KeyUsageFlags.NonRepudiation) <> X509KeyUsageFlags.None) Then
                        nextDbgInfo.keyUsageNR = True
                    End If
                End If
            Next
            nextDbgInfo.isPrivate = nextCert.HasPrivateKey
            ret.certList.Add(nextDbgInfo)

        Next

        Return ret
    End Function

    Public Function getThumbprint() As String
        Return signer.getThumbprint
    End Function

    Public Function getKeySize() As Integer
        Return signer.getKeySize
    End Function


    Public Function sign(hashAlg As String, contentB64 As String) As String
        Return signer.sign(hashAlg, contentB64)
    End Function

    Public Function sign(hashAlg As Integer, contentB64 As String) As String
        Return signer.sign(hashAlg, contentB64)
    End Function

    Public Function getCertificateByThumbprint(thumbprint As String) As String
        Return signer.getCertificateByThumbprint(thumbprint)
    End Function

    Public Function getKeySizeByThumbprint(thumbprint As String) As Integer
        Return signer.getKeySizeByThumbprint(thumbprint)
    End Function

    Public Function getCertificateBySubject(subject As String) As String
        Return signer.getCertificateBySubject(subject)
    End Function


End Module

