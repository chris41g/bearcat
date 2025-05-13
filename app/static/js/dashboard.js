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
    
    // Validate chart data
    if (!chartData || !chartData.sessions || !chartData.os_distribution) {
        console.error("Invalid chart data structure:", chartData);
        return;
    }
    
// Host Trends Chart - Online hosts focused
const trendsCtx = document.getElementById('hostTrendsChart');
if (trendsCtx && chartData.sessions.labels.length > 0) {
    trendChart = new Chart(trendsCtx, {
        type: 'line',
        data: {
            labels: chartData.sessions.labels,
            datasets: [
                {
                    label: 'Online Hosts',
                    data: chartData.sessions.online_hosts,
                    borderColor: bearcatColors.primary,
                    backgroundColor: 'rgba(101, 29, 50, 0.2)',
                    borderWidth: 3,
                    fill: true,
                    tension: 0.3,
                    pointRadius: 6,
                    pointHoverRadius: 8,
                    pointBackgroundColor: bearcatColors.primary,
                    pointBorderColor: '#fff',
                    pointBorderWidth: 2,
                    yAxisID: 'y'
                },
                {
                    label: 'Online Percentage',
                    data: chartData.sessions.percentages,
                    borderColor: bearcatColors.secondary,
                    backgroundColor: 'rgba(138, 40, 70, 0.1)',
                    borderWidth: 2,
                    fill: false,
                    tension: 0.3,
                    pointRadius: 4,
                    pointHoverRadius: 6,
                    borderDash: [3, 3],
                    yAxisID: 'y1'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    type: 'linear',
                    display: true,
                    position: 'left',
                    beginAtZero: true,
                    title: {
                        display: true,
                        text: 'Number of Hosts',
                        color: bearcatColors.primary,
                        font: {
                            weight: 'bold'
                        }
                    },
                    ticks: {
                        color: bearcatColors.primary
                    }
                },
                y1: {
                    type: 'linear',
                    display: true,
                    position: 'right',
                    max: 100,
                    min: 0,
                    title: {
                        display: true,
                        text: 'Online Percentage (%)',
                        color: bearcatColors.secondary
                    },
                    ticks: {
                        color: bearcatColors.secondary,
                        callback: function(value) {
                            return value + '%';
                        }
                    },
                    grid: {
                        drawOnChartArea: false,
                    },
                }
            },
            plugins: {
                legend: {
                    position: 'top',
                    labels: {
                        usePointStyle: true,
                        padding: 20
                    }
                },
                tooltip: {
                    mode: 'index',
                    intersect: false,
                    callbacks: {
                        label: function(context) {
                            if (context.datasetIndex === 0) {
                                return 'Online Hosts: ' + context.parsed.y;
                            }
                            return 'Online: ' + context.parsed.y.toFixed(1) + '%';
                        }
                    }
                }
            }
        }
    });
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
    if (document.getElementById('hostTrendsChart') && document.getElementById('osDistributionChart')) {
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
