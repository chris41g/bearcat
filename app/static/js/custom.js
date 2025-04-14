// Custom JavaScript for Network Discovery Web Interface

document.addEventListener('DOMContentLoaded', function() {
    // Initialize tooltips
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
    
    // Auto-dismiss alerts after 5 seconds
    setTimeout(function() {
        var alerts = document.querySelectorAll('.alert:not(.alert-permanent)');
        alerts.forEach(function(alert) {
            var bsAlert = new bootstrap.Alert(alert);
            bsAlert.close();
        });
    }, 5000);
    
    // Socket.IO connection status indicator and enhanced debugging
    if (typeof io !== 'undefined') {
        console.log("Socket.IO is available, setting up connection");
        var socket = io();
        var statusDiv = document.createElement('div');
        statusDiv.className = 'socket-status';
        document.body.appendChild(statusDiv);
        
        socket.on('connect', function() {
            console.log("Socket.IO connected");
            statusDiv.className = 'socket-status socket-connected';
            statusDiv.innerHTML = '<i class="fas fa-plug me-1"></i> Connected';
            statusDiv.style.display = 'block';
            setTimeout(function() {
                statusDiv.style.display = 'none';
            }, 3000);
        });
        
        socket.on('disconnect', function() {
            console.log("Socket.IO disconnected");
            statusDiv.className = 'socket-status socket-disconnected';
            statusDiv.innerHTML = '<i class="fas fa-plug-circle-xmark me-1"></i> Disconnected';
            statusDiv.style.display = 'block';
        });
        
        // Handle scan updates via Socket.IO
        socket.on('scan_update', function(data) {
            console.log("Received scan update:", data);
            
            // Update running scans if present
            var scanElem = document.querySelector('[data-scan-id="' + data.id + '"]');
            if (scanElem) {
                console.log("Found scan element for ID: " + data.id);
                // Update progress bar
                var progressBar = scanElem.querySelector('.progress-bar');
                if (progressBar) {
                    console.log("Updating progress bar to " + data.progress + "%");
                    progressBar.style.width = data.progress + '%';
                    progressBar.setAttribute('aria-valuenow', data.progress);
                    progressBar.textContent = data.progress.toFixed(1) + '%';
                } else {
                    console.log("Progress bar element not found");
                }
                
                // Update host counts
                var hostCounts = scanElem.querySelector('.host-counts');
                if (hostCounts) {
                    console.log("Updating host counts");
                    hostCounts.textContent = data.hosts_scanned + ' / ' + data.total_hosts + ' hosts (' + data.hosts_online + ' online)';
                } else {
                    console.log("Host counts element not found");
                }
                
                // If completed, refresh the page to update stats
                if (data.status === 'completed' || data.status === 'failed') {
                    console.log("Scan completed or failed, refreshing page");
                    setTimeout(function() {
                        window.location.reload();
                    }, 2000);
                }
            } else {
                console.log("No scan element found for ID: " + data.id);
            }
        });
    } else {
        console.warn("Socket.IO is not available");
    }
    
    // Running scan progress updater - fallback for Socket.IO
    function updateScanProgress() {
        var runningScanElements = document.querySelectorAll('[data-scan-id]');
        console.log("Checking for scan elements to update: " + runningScanElements.length);
        
        runningScanElements.forEach(function(element) {
            var scanId = element.getAttribute('data-scan-id');
            console.log("Fetching progress for scan ID: " + scanId);
            
            fetch('/scans/' + scanId + '/progress')
                .then(response => response.json())
                .then(data => {
                    console.log("Received scan progress:", data);
                    // Update progress bar
                    var progressBar = element.querySelector('.progress-bar');
                    if (progressBar) {
                        console.log("Updating progress bar to " + data.progress + "%");
                        progressBar.style.width = data.progress + '%';
                        progressBar.setAttribute('aria-valuenow', data.progress);
                        progressBar.textContent = data.progress.toFixed(1) + '%';
                    }
                    
                    // Update host counts
                    var hostCountsElement = element.querySelector('.host-counts');
                    if (hostCountsElement) {
                        console.log("Updating host counts");
                        hostCountsElement.textContent = data.hosts_scanned + ' / ' + data.total_hosts + ' hosts (' + data.hosts_online + ' online)';
                    }
                    
                    // If status changed to completed, refresh the page
                    if (data.status === 'completed' || data.status === 'failed') {
                        console.log("Scan completed or failed, refreshing page");
                        setTimeout(function() {
                            window.location.reload();
                        }, 2000);
                    }
                })
                .catch(error => console.error('Error fetching scan progress:', error));
        });
    }
    
    // If there are running scans, update progress periodically (fallback)
    if (document.querySelectorAll('[data-scan-id]').length > 0) {
        console.log("Found running scans, setting up periodic updates");
        updateScanProgress();
        setInterval(updateScanProgress, 5000);
    }
    
    // Confirm potentially dangerous actions
    var dangerForms = document.querySelectorAll('form[data-confirm]');
    dangerForms.forEach(function(form) {
        form.addEventListener('submit', function(event) {
            var confirmMessage = form.getAttribute('data-confirm');
            if (!confirm(confirmMessage)) {
                event.preventDefault();
            }
        });
    });
    
    // Custom file input
    var fileInputs = document.querySelectorAll('.custom-file-input');
    fileInputs.forEach(function(input) {
        input.addEventListener('change', function(e) {
            var fileName = e.target.files[0].name;
            var nextSibling = e.target.nextElementSibling;
            nextSibling.innerText = fileName;
        });
    });
    
    // Copy to clipboard functionality
    var copyButtons = document.querySelectorAll('.btn-copy');
    copyButtons.forEach(function(button) {
        button.addEventListener('click', function() {
            var target = document.querySelector(button.getAttribute('data-copy-target'));
            var textToCopy = target.innerText || target.value;
            
            // Create temporary textarea to copy from
            var textarea = document.createElement('textarea');
            textarea.value = textToCopy;
            textarea.setAttribute('readonly', '');
            textarea.style.position = 'absolute';
            textarea.style.left = '-9999px';
            document.body.appendChild(textarea);
            
            // Select and copy
            textarea.select();
            document.execCommand('copy');
            
            // Clean up
            document.body.removeChild(textarea);
            
            // Show feedback
            var originalText = button.innerHTML;
            button.innerHTML = '<i class="fas fa-check"></i> Copied!';
            setTimeout(function() {
                button.innerHTML = originalText;
            }, 2000);
        });
    });
    
    // Dashboard refresh
    var refreshButton = document.getElementById('refreshDashboard');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            refreshButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
            refreshButton.disabled = true;
            
            // Refresh stats
            fetch('/api/dashboard/stats')
                .then(response => response.json())
                .then(data => {
                    // Update stats
                    document.getElementById('totalHosts').textContent = data.total_hosts;
                    document.getElementById('onlineHosts').textContent = data.online_hosts;
                    document.getElementById('onlinePercentage').textContent = data.online_percentage.toFixed(1) + '%';
                    
                    // Refresh charts
                    return fetch('/api/dashboard/charts');
                })
                .then(response => response.json())
                .then(data => {
                    // Update charts (would need to refresh Chart.js instances)
                    refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                    refreshButton.disabled = false;
                })
                .catch(error => {
                    console.error('Error refreshing dashboard:', error);
                    refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                    refreshButton.disabled = false;
                });
        });
    }
    
    // Query parameter builder for predefined queries
    var queryTypeSelect = document.getElementById('query_type');
    var queryParamsContainer = document.getElementById('query_params_container');
    
    if (queryTypeSelect && queryParamsContainer) {
        queryTypeSelect.addEventListener('change', function() {
            var queryType = queryTypeSelect.value;
            
            // Hide all parameter fields
            var paramFields = queryParamsContainer.querySelectorAll('.param-field');
            paramFields.forEach(function(field) {
                field.style.display = 'none';
            });
            
            // Show relevant parameter fields based on query type
            if (queryType === 'hosts_with_port') {
                document.getElementById('port_param').style.display = 'block';
            } else if (queryType === 'hosts_with_software') {
                document.getElementById('software_param').style.display = 'block';
            }
        });
        
        // Trigger change event on page load
        queryTypeSelect.dispatchEvent(new Event('change'));
    }
});
