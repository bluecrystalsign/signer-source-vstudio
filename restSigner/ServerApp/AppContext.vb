
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
Imports System.Collections.Generic
Imports System.ComponentModel
Imports System.Data
Imports System.Drawing
Imports System.Linq
Imports System.Net
Imports System.Net.Sockets
Imports System.Text
Imports System.Threading
Imports System.Windows.Forms
Imports System.Web.Script.Serialization
Imports System.Uri
Imports System.Web.HttpUtility
Imports System.Web

Public Class AppContext
    Inherits ApplicationContext



#Region " Storage "

    Private WithEvents Tray As NotifyIcon
    Private WithEvents MainMenu As ContextMenuStrip
    Private WithEvents mnuDisplayForm As ToolStripMenuItem
    Private WithEvents mnuSep1 As ToolStripSeparator
    Private WithEvents mnuExit As ToolStripMenuItem
    Private WithEvents mnuAbout As ToolStripMenuItem

    Private tcpListener As TcpListener
    Private listenThread As Thread
    Private connectedClients As Integer = 0
    Private Delegate Sub WriteMessageDelegate(ByVal msg As String)
    Private messageVersion As String
    Private messageBrand As String


#End Region

#Region " Constructor "

    Public Sub New()
        'Initialize the menus
        mnuSep1 = New ToolStripSeparator()
        mnuAbout = New ToolStripMenuItem("Sobre")
        mnuExit = New ToolStripMenuItem("Encerrar")
        MainMenu = New ContextMenuStrip
        MainMenu.Items.AddRange(New ToolStripItem() {mnuAbout})
        MainMenu.Items.AddRange(New ToolStripItem() {mnuExit})
        messageVersion = "REST Signer v1.6.0"
        messageBrand = "Blue Crystal"
        'Initialize the tray
        Tray = New NotifyIcon
        Tray.Icon = My.Resources.TrayIcon
        Tray.ContextMenuStrip = MainMenu
        Tray.Text = messageBrand + " " + messageVersion

        'AddHandler Tray.BalloonTipClicked, AddressOf BalloonTipClicked
        'AddHandler Tray.Click, AddressOf BalloonTipClicked

        'Display
        Tray.Visible = True

        Tray.ShowBalloonTip(1000, messageBrand, messageVersion + " em execução", ToolTipIcon.Info)


        Server()
    End Sub


    Private Shared Sub BalloonTipClicked(sender As Object, e As EventArgs)
        'MessageBox.Show(String.Format("Clicked on Notifier for document", "message"))
    End Sub

#End Region

#Region " Server "

    Private Sub Server()
        Me.tcpListener = New TcpListener(IPAddress.Loopback, 8612) ' Change to IPAddress.Any for internet wide Communication
        Me.listenThread = New Thread(New ThreadStart(AddressOf ListenForClients))
        Me.listenThread.Start()
    End Sub

    Private Sub ListenForClients()
        Me.tcpListener.Start()

        Do
            Try
                Dim client As TcpClient = Me.tcpListener.AcceptTcpClient()
                connectedClients += 1
                Dim clientThread As New Thread(New ParameterizedThreadStart(AddressOf HandleClientComm))
                clientThread.Start(client)
            Catch
                Return
            End Try
        Loop
    End Sub

    Private Sub HandleClientComm(ByVal client As Object)
        Dim tcpClient As TcpClient = DirectCast(client, TcpClient)
        Dim clientStream As NetworkStream = tcpClient.GetStream()

        Dim message(100000) As Byte
        Dim bytesRead As Integer

        Do
            bytesRead = 0

            Try
                'blocks until a client sends a message
                bytesRead = clientStream.Read(message, 0, 100000)
            Catch
                'a socket error has occured
                Exit Do
            End Try

            If bytesRead = 0 Then
                'the client has disconnected from the server
                connectedClients -= 1
                'lblNumberOfConnections.Text = connectedClients.ToString()
                Exit Do
            End If

            'message has successfully been received
            Dim encoder As New ASCIIEncoding()

            ' Convert the Bytes received to a string and display it on the Server Screen
            Dim msg As String = encoder.GetString(message, 0, bytesRead)

            Run(msg, encoder, clientStream)
        Loop

        tcpClient.Close()
    End Sub

    Private Sub Run(ByVal msg As String, ByVal encoder As ASCIIEncoding, ByVal clientStream As NetworkStream)
        Dim jsonOut As String = ""
        Dim buffer() As Byte
        'Dim parts As String() = Split(msg, vbCrLf + "" + vbCrLf)
        Dim parts As String() = msg.Split(New Char() {" "c})
        Dim jsonIn As String = parts(1)

        If msg.StartsWith("GET /test") Then
            jsonOut = test()
        ElseIf msg.StartsWith("GET /cert") Then
            jsonOut = cert(jsonIn)
        ElseIf msg.StartsWith("GET /keySize") Then
            jsonOut = keySize(jsonIn)
        ElseIf msg.StartsWith("OPTIONS /sign") Then
            jsonOut = options()
        ElseIf msg.StartsWith("PUT /sign") Then
            jsonOut = putSign(jsonIn)
        ElseIf msg.StartsWith("GET /sign") Then
            jsonOut = getSign(jsonIn)
        ElseIf msg.StartsWith("GET /debug") Then
            jsonOut = debugInfo()
        Else
            Dim header404 As String = "HTTP/1.x 404 NOT FOUND" + vbCrLf + "Connection: Close()" + vbCrLf + "Content-Type: text/html; charset=UTF-8" + vbCrLf + vbCrLf + "Error 404: File not found."
            buffer = encoder.GetBytes(header404)
            clientStream.Write(buffer, 0, buffer.Length)
            clientStream.Flush()
            clientStream.Close()
            Return
        End If

        Dim header As String = "HTTP/1.x 200 OK" + vbCrLf + "Connection: Close()" + vbCrLf + "Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept" + vbCrLf + "Access-Control-Allow-Origin: *" + vbCrLf + "Access-Control-Allow-Methods: GET, POST" + vbCrLf + "Content-Type: application/json" + vbCrLf + vbCrLf

        buffer = encoder.GetBytes(header)
        clientStream.Write(buffer, 0, buffer.Length)

        buffer = encoder.GetBytes(jsonOut)

        clientStream.Write(buffer, 0, buffer.Length)
        clientStream.Flush()
        clientStream.Close()
    End Sub


    Function options() As String
        Return ""
    End Function

    Function keySize(jsonIn As String) As String
        Dim jsonSerializer As New JavaScriptSerializer
        'Dim keySizeRequest As KeySizeRequest = jsonSerializer.Deserialize(Of KeySizeRequest)(jsonIn)

        Dim myUri As New Uri("http://localhost/" + jsonIn)
        Dim thumbprint As String = HttpUtility.ParseQueryString(myUri.Query).Get("thumbprint")

        Dim keySizeResponse As New KeySizeResponse
        keySizeResponse.size = getKeySizeByThumbprint(thumbprint)


        Dim jsonOut As String = jsonSerializer.Serialize(keySizeResponse)

        Return jsonOut
    End Function

    Function test() As String
        Dim jsonSerializer As New JavaScriptSerializer

        Dim testresponse As New TestResponse
        testresponse.provider = "BluC REST Signer v1.6.0"
        testresponse.status = "OK"
        Dim jsonOut As String = jsonSerializer.Serialize(testresponse)

        Return jsonOut
    End Function

    Function debugInfo() As String
        Dim jsonSerializer As New JavaScriptSerializer

        Dim dbgInfo As DebugInfo = New DebugInfo
        dbgInfo = BluC.debugInfo()

        Dim resp As DebugResponse = New DebugResponse

        resp.certInfo = dbgInfo

        Dim jsonOut As String = jsonSerializer.Serialize(resp)
        Return jsonOut
    End Function


    Function cert(jsonIn As String) As String
        Dim jsonSerializer As New JavaScriptSerializer

        'Dim certificaterequest As CertificateRequest = jsonSerializer.Deserialize(Of CertificateRequest)(jsonIn)

        Dim certificateresponse As New CertificateResponse
        certificateresponse.certificate = getCertificate("Assinatura Digital", "Escolha o certificado que será utilizado na assinatura.", "", "")
        certificateresponse.subject = getSubject()
        certificateresponse.thumbprint = getThumbprint()
        Dim jsonOut As String = jsonSerializer.Serialize(certificateresponse)

        Return jsonOut
    End Function

    Function getSign(jsonIn As String) As String
        Dim jsonSerializer As New JavaScriptSerializer

        'Dim signrequest As SignRequest = jsonSerializer.Deserialize(Of SignRequest)(jsonIn)
        Dim signrequest As SignRequest = New SignRequest

        Dim myUri As New Uri("http://localhost/" + jsonIn)
        signrequest.subject = HttpUtility.ParseQueryString(myUri.Query).Get("subject")
        signrequest.thumbprint = HttpUtility.ParseQueryString(myUri.Query).Get("thumbprint")
        signrequest.hashAlg = HttpUtility.ParseQueryString(myUri.Query).Get("hashAlg")
        signrequest.payload = HttpUtility.ParseQueryString(myUri.Query).Get("payload")

        If signrequest.subject <> Nothing Then
            Dim s As String = BluC.getCertificateBySubject(signrequest.subject)
        End If

        If signrequest.thumbprint <> Nothing Then
            Dim s As String = BluC.getCertificateByThumbprint(signrequest.thumbprint)
        End If

        Dim signresponse As New SignResponse

        If signrequest.hashAlg <> Nothing Then
            If signrequest.hashAlg = "PKCS7" Or signrequest.hashAlg = "sha1" Then
                signresponse.sign = BluC.sign("sha1", signrequest.payload)
            Else
                signresponse.sign = BluC.sign("sha256", signrequest.payload)
            End If

        Else
            Dim keySize = getKeySize()
            If keySize < 2048 Or signrequest.policy = "PKCS7" Then
                signresponse.sign = BluC.sign("sha1", signrequest.payload)
            Else
                signresponse.sign = BluC.sign("sha256", signrequest.payload)
            End If

        End If


        signresponse.subject = getSubject()
        signresponse.thumbprint = getThumbprint()
        signresponse.errormsg = ""

        Dim jsonOut As String = jsonSerializer.Serialize(signresponse)

        Return jsonOut
    End Function

    Function putSign(jsonIn As String) As String
        Dim jsonSerializer As New JavaScriptSerializer

        Dim signrequest As SignRequest = jsonSerializer.Deserialize(Of SignRequest)(jsonIn)

        If signrequest.subject <> Nothing Then
            Dim s As String = BluC.getCertificateBySubject(signrequest.subject)
        End If

        If signrequest.thumbprint <> Nothing Then
            Dim s As String = BluC.getCertificateByThumbprint(signrequest.thumbprint)
        End If

        Dim signresponse As New SignResponse

        If signrequest.hashAlg <> Nothing Then
            If signrequest.hashAlg = "PKCS7" Or signrequest.hashAlg = "sha1" Then
                signresponse.sign = BluC.sign("sha1", signrequest.payload)
            Else
                signresponse.sign = BluC.sign("sha256", signrequest.payload)
            End If

        Else
            Dim keySize = getKeySize()
            If keySize < 2048 Or signrequest.policy = "PKCS7" Then
                signresponse.sign = BluC.sign("sha1", signrequest.payload)
            Else
                signresponse.sign = BluC.sign("sha256", signrequest.payload)
            End If

        End If


        signresponse.subject = getSubject()
        signresponse.thumbprint = getThumbprint()
        signresponse.errormsg = ""

        Dim jsonOut As String = jsonSerializer.Serialize(signresponse)

        Return jsonOut
    End Function

    'Private Monsters As New List(Of Monster)
    'later add them into this collection
    'Monsters.Add(New Monster(50, 20, 5))

    Public Class DebugResponse
        Public certInfo As DebugInfo
    End Class

    Private Class TestResponse
        Public provider As String
        Public status As String
        Public errormsg As String
    End Class
    Private Class KeySizeRequest
        Public thumbprint As String
    End Class

    Private Class KeySizeResponse
        Public size As Integer
        Public errormsg As String
    End Class
    Private Class CertificateRequest
    End Class

    Private Class CertificateResponse
        Public certificate As String
        Public subject As String
        Public thumbprint As String
        Public errormsg As String
    End Class

    Private Class SignRequest
        Public payload As String
        Public certificate As String
        Public subject As String
        Public thumbprint As String
        Public policy As String
        Public hashAlg As String
    End Class

    Private Class SignResponse
        Public sign As String
        Public subject As String
        Public thumbprint As String
        Public errormsg As String
    End Class

#End Region

#Region " Event handlers "

    Private Sub AppContext_ThreadExit(ByVal sender As Object, ByVal e As System.EventArgs) _
    Handles Me.ThreadExit
        Tray.Visible = False
    End Sub


    Private Sub mnuExit_Click(ByVal sender As Object, ByVal e As System.EventArgs) _
    Handles mnuExit.Click
        Me.tcpListener.Stop()
        Application.Exit()
    End Sub

    Private Sub mnuAbout_Click(ByVal sender As Object, ByVal e As System.EventArgs) _
    Handles mnuAbout.Click
        MessageBox.Show(messageVersion)
    End Sub

#End Region

End Class