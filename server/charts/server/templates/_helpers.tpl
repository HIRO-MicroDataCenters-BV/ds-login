{{/* vim: set filetype=mustache: */}}

{{- define "ds-login.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ds-login.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- /* Collapse 'ds-login-ds-login' → 'ds-login' when the release name
       already starts with the chart name. Matches the canonical Helm
       helper template; without this, every Service/Deployment ends up
       with the chart name doubled and consumers have to configure the
       awkward 'ds-login-ds-login' DNS. */ -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ds-login.labels" -}}
app.kubernetes.io/name: {{ include "ds-login.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "ds-login.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ds-login.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ds-login.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ds-login.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}
