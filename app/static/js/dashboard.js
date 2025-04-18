// Dashboard-specific JavaScript for Bearcat Active Discovery

// Track chart instances to prevent multiple initializations
let trendChart = null;
let osChart = null;

// Define Bearcat color palette
const bearcatColors = {
    primary: '#651D32',    // Main maroon
    secondary: '#8A2846',  // Lighter maroon
    gray: '#4A4A4A',       // Dark gray
    lightGray: '#777777',  // Light gray
    // Add more shades as needed
    chartColors: [
        '#651D32', '#8A2846', '#4A4A4A', '#777777', '#B33B59', 
        '#964355', '#593035', '#2E1A1F', '#CCB3BB', '#E6D7DB'
    ]
};

function initDashboardCharts(chartData) {
    console.log("Initializing dashboard charts with data:", chartData);
    
    // Destroy existing charts if they exist
    if (trendChart) {
        trendChart.destroy();
    }
    
    if (osChart) {
        osChart.destroy();
    }
    
    // Host Trends Chart
    const trendsCtx = document.getElementById('hostTrendsChart');
    if (trendsCtx && chartData.sessions && chartData.sessions.labels && chartData.sessions.labels.length > 0) {
        trendChart = new Chart(trendsCtx, {
            type: 'line',
            data: {
                labels: chartData.sessions.labels,
                datasets: [
                    {
                        label: 'Online Hosts',
                        data: chartData.sessions.online_hosts,
                        borderColor: bearcatColors.secondary,
                        backgroundColor: 'rgba(138, 40, 70, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    },
                    {
                        label: 'Total Hosts',
                        data: chartData.sessions.total_hosts,
                        borderColor: bearcatColors.primary,
                        backgroundColor: 'rgba(101, 29, 50, 0.1)',
                        borderWidth: 2,
                        fill: true,
                        tension: 0.4
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
    
    // OS Distribution Chart
    const osCtx = document.getElementById('osDistributionChart');
    if (osCtx && chartData.os_distribution && chartData.os_distribution.labels && chartData.os_distribution.labels.length > 0) {
        osChart = new Chart(osCtx, {
            type: 'doughnut',
            data: {
                labels: chartData.os_distribution.labels,
                datasets: [{
                    data: chartData.os_distribution.counts,
                    backgroundColor: bearcatColors.chartColors,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right'
                    }
                }
            }
        });
    }
}

// Add event listener for dashboard page
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize charts if we're on the dashboard page
    if (document.getElementById('hostTrendsChart') && document.getElementById('osDistributionChart')) {
        // Get chart data from the template
        const chartDataElement = document.getElementById('chart-data');
        if (chartDataElement) {
            try {
                const chartData = JSON.parse(chartDataElement.textContent);
                initDashboardCharts(chartData);
            } catch (e) {
                console.error("Error parsing chart data:", e);
            }
        }
    }
    
    // Add refresh button handler
    const refreshButton = document.getElementById('refreshDashboard');
    if (refreshButton) {
        refreshButton.addEventListener('click', function() {
            refreshButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Refreshing...';
            refreshButton.disabled = true;
            
            // Fetch fresh data
            fetch('/api/dashboard/charts')
                .then(response => response.json())
                .then(data => {
                    initDashboardCharts(data);
                    refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                    refreshButton.disabled = false;
                })
                .catch(error => {
                    console.error('Error refreshing charts:', error);
                    refreshButton.innerHTML = '<i class="fas fa-sync-alt"></i> Refresh';
                    refreshButton.disabled = false;
                });
        });
    }
});
