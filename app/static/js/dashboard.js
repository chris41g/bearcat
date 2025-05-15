// Dashboard-specific JavaScript for Sidney

// Track chart instances to prevent multiple initializations
let vlanChart = null;
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
    if (vlanChart) {
        vlanChart.destroy();
    }
    
    if (osChart) {
        osChart.destroy();
    }
    
    // Validate chart data
    if (!chartData || !chartData.vlan_distribution || !chartData.os_distribution) {
        console.error("Invalid chart data structure:", chartData);
        return;
    }
    
    // VLAN Distribution Chart
    const vlanCtx = document.getElementById('vlanDistributionChart');
    if (vlanCtx && chartData.vlan_distribution.labels.length > 0) {
        vlanChart = new Chart(vlanCtx, {
            type: 'doughnut',
            data: {
                labels: chartData.vlan_distribution.labels,
                datasets: [{
                    data: chartData.vlan_distribution.counts,
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
    } else {
        console.warn("No VLAN distribution data available or canvas element not found");
    }
    
    // OS Distribution Chart
    const osCtx = document.getElementById('osDistributionChart');
    if (osCtx && chartData.os_distribution.labels.length > 0) {
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
    } else {
        console.warn("No OS distribution data available or canvas element not found");
    }
}

// Add event listener for dashboard page
document.addEventListener('DOMContentLoaded', function() {
    // Only initialize charts if we're on the dashboard page
    if (document.getElementById('vlanDistributionChart') && document.getElementById('osDistributionChart')) {
        // Get chart data from the template
        const chartDataElement = document.getElementById('chart-data');
        if (chartDataElement) {
            try {
                const chartData = JSON.parse(chartDataElement.textContent);
                console.log("Parsed chart data:", chartData);
                initDashboardCharts(chartData);
            } catch (e) {
                console.error("Error parsing chart data:", e);
                console.error("Chart data content:", chartDataElement.textContent);
            }
        } else {
            console.error("Chart data element not found");
        }
    }
});
