Public Class DebugInfo
    Public certList As New List(Of DbgAppCerts)

End Class

Public Class DbgAppCerts
    Public subject As String
    Public subjectOk As Boolean
    Public issuer As String
    Public issuerOk As Boolean
    Public notBefore As DateTime
    Public notAfter As DateTime
    Public datesOk As Boolean
    Public keyUsage As Boolean
    Public isPrivate As Boolean


End Class
