// Main JavaScript file for the DSSE System

document.addEventListener('DOMContentLoaded', function() {
    // Initialize Bootstrap tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });

    // Auto-close alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);

    // File Input Enhancement - Show selected filename
    var fileInputs = document.querySelectorAll('input[type="file"]');
    fileInputs.forEach(function(input) {
        input.addEventListener('change', function(e) {
            var fileName = e.target.files[0].name;
            var fileSize = (e.target.files[0].size / 1024).toFixed(1) + ' KB';
            
            // Find the closest label or create a new status element
            var parent = this.parentElement;
            var statusElement = parent.querySelector('.file-status');
            
            if (!statusElement) {
                statusElement = document.createElement('div');
                statusElement.className = 'file-status mt-2 small';
                parent.appendChild(statusElement);
            }
            
            statusElement.innerHTML = '<i class="fas fa-check-circle text-success me-1"></i>' + 
                                    'Selected: <strong>' + fileName + '</strong> (' + fileSize + ')';
        });
    });
});

// Function to toggle password visibility
function togglePasswordVisibility(inputId, iconId) {
    const passwordInput = document.getElementById(inputId);
    const icon = document.getElementById(iconId);
    
    if (passwordInput.type === 'password') {
        passwordInput.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        passwordInput.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Function to copy text to clipboard
function copyToClipboard(text, alertId) {
    navigator.clipboard.writeText(text).then(function() {
        const alertElement = document.getElementById(alertId);
        alertElement.classList.remove('d-none');
        
        setTimeout(function() {
            alertElement.classList.add('d-none');
        }, 2000);
    }).catch(function(err) {
        console.error('Could not copy text: ', err);
    });
}
