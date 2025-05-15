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
    
    // VLAN Distribution Bar Chart with count labels
    const vlanCtx = document.getElementById('vlanDistributionChart');
    if (vlanCtx && chartData.vlan_distribution.labels.length > 0) {
        // Calculate the maximum value to determine padding needed
        const maxValue = Math.max(...chartData.vlan_distribution.counts);
        
        vlanChart = new Chart(vlanCtx, {
            type: 'bar',
            data: {
                labels: chartData.vlan_distribution.labels,
                datasets: [{
                    label: 'Host Count',
                    data: chartData.vlan_distribution.counts,
                    backgroundColor: bearcatColors.primary,
                    borderColor: bearcatColors.secondary,
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                // Add layout padding to accommodate labels
                layout: {
                    padding: {
                        top: 30,  // Extra space at top for labels
                        left: 0,
                        right: 0,
                        bottom: 0
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        // Add padding to the max value so labels don't get cut off
                        max: maxValue * 1.1,
                        ticks: {
                            stepSize: Math.max(1, Math.floor(maxValue / 10)),
                            precision: 0
                        },
                        title: {
                            display: true,
                            text: 'Number of Hosts'
                        }
                    },
                    x: {
                        title: {
                            display: true,
                            text: 'VLAN'
                        }
                    }
                },
                plugins: {
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: function(context) {
                                return `${context.label}: ${context.parsed.y} hosts`;
                            }
                        }
                    }
                },
                // Use animation onComplete callback to draw labels
                animation: {
                    onComplete: function() {
                        const chart = this;
                        const ctx = chart.ctx;
                        
                        ctx.save();
                        ctx.font = 'bold 14px Arial';
                        ctx.fillStyle = '#333333';
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'bottom';
                        
                        chart.data.datasets.forEach((dataset, i) => {
                            const meta = chart.getDatasetMeta(i);
                            
                            meta.data.forEach((element, index) => {
                                const value = dataset.data[index];
                                const position = element.tooltipPosition();
                                
                                // Draw the count above the bar with extra spacing for tall bars
                                const labelY = position.y - 8;
                                ctx.fillText(value, position.x, labelY);
                            });
                        });
                        
                        ctx.restore();
                    }
                }
            }
        });
        
        // Force a redraw to ensure labels appear
        setTimeout(() => {
            if (vlanChart) {
                vlanChart.update('none');
            }
        }, 100);
        
    } else {
        console.warn("No VLAN distribution data available or canvas element not found");
    }
    
    // OS Distribution Chart (keeping as doughnut)
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
