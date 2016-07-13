Public Class DebugInfo
    Public certList As New List(Of DbgAppCerts)

End Class

Public Class DbgAppCerts
    Public subject As String
    Public issuer As String
    Public notBefore As String
    Public notAfter As String
    Public keyUsageDS As Boolean
    Public keyUsageNR As Boolean
    Public isPrivate As Boolean


End Class
