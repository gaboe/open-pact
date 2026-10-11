{{- define "open-pact.secretName" -}}
{{- if .Values.postgres.existingSecret }}{{ .Values.postgres.existingSecret }}{{ else }}{{ .Release.Name }}-postgres{{ end -}}
{{- end -}}
