/**
 * Re-movery Web应用JavaScript
 */

// 全局变量
let severityChart = null;
let vulnerabilityChart = null;

// 初始化应用
document.addEventListener('DOMContentLoaded', function() {
    // 初始化图表
    initCharts();
    
    // 加载设置
    loadSettings();
    
    // 绑定事件
    bindEvents();
});

// 初始化图表
function initCharts() {
    // 漏洞严重程度分布图
    const severityCtx = document.getElementById('severity-chart').getContext('2d');
    severityChart = new Chart(severityCtx, {
        type: 'pie',
        data: {
            labels: ['高危', '中危', '低危'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#dc3545', '#fd7e14', '#0dcaf0']
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    position: 'bottom'
                }
            }
        }
    });

    // 常见漏洞类型图
    const vulnerabilityCtx = document.getElementById('vulnerability-chart').getContext('2d');
    vulnerabilityChart = new Chart(vulnerabilityCtx, {
        type: 'bar',
        data: {
            labels: [],
            datasets: [{
                label: '漏洞数量',
                data: [],
                backgroundColor: '#0d6efd'
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// 加载设置
function loadSettings() {
    const settings = JSON.parse(localStorage.getItem('re-movery-settings') || '{}');
    document.getElementById('confidence-threshold').value = settings.confidenceThreshold || 0.7;
    document.getElementById('confidence-value').textContent = settings.confidenceThreshold || 0.7;
    document.getElementById('default-parallel').checked = settings.defaultParallel !== false;
    document.getElementById('default-incremental').checked = settings.defaultIncremental !== false;
    
    // 应用设置到扫描表单
    document.getElementById('parallel').checked = settings.defaultParallel !== false;
    document.getElementById('incremental').checked = settings.defaultIncremental !== false;
}

// 保存设置
function saveSettings() {
    const settings = {
        confidenceThreshold: parseFloat(document.getElementById('confidence-threshold').value),
        defaultParallel: document.getElementById('default-parallel').checked,
        defaultIncremental: document.getElementById('default-incremental').checked
    };
    localStorage.setItem('re-movery-settings', JSON.stringify(settings));
    alert('设置已保存');
    
    // 应用设置到扫描表单
    document.getElementById('parallel').checked = settings.defaultParallel;
    document.getElementById('incremental').checked = settings.defaultIncremental;
}

// 绑定事件
function bindEvents() {
    // 设置表单提交
    document.getElementById('settings-form').addEventListener('submit', function(e) {
        e.preventDefault();
        saveSettings();
    });

    // 更新置信度值显示
    document.getElementById('confidence-threshold').addEventListener('input', function() {
        document.getElementById('confidence-value').textContent = this.value;
    });

    // 文件扫描表单提交
    document.getElementById('file-scan-form').addEventListener('submit', function(e) {
        e.preventDefault();
        scanFile();
    });

    // 目录扫描表单提交
    document.getElementById('directory-scan-form').addEventListener('submit', function(e) {
        e.preventDefault();
        scanDirectory();
    });
}

// 扫描文件
function scanFile() {
    const fileInput = document.getElementById('file');
    if (!fileInput.files.length) {
        alert('请选择文件');
        return;
    }

    const formData = new FormData();
    formData.append('file', fileInput.files[0]);

    // 显示加载指示器
    showLoading('正在扫描文件...');

    fetch('/scan/file', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('扫描请求失败');
        }
        return response.json();
    })
    .then(data => {
        hideLoading();
        updateResults(data);
        // 切换到结果标签页
        document.querySelector('a[href="#results"]').click();
    })
    .catch(error => {
        hideLoading();
        console.error('Error:', error);
        alert('扫描失败: ' + error.message);
    });
}

// 扫描目录
function scanDirectory() {
    const directory = document.getElementById('directory').value;
    if (!directory) {
        alert('请输入目录路径');
        return;
    }

    const formData = new FormData();
    formData.append('directory', directory);
    
    const exclude = document.getElementById('exclude').value;
    if (exclude) {
        exclude.split(',').forEach(pattern => {
            formData.append('exclude', pattern.trim());
        });
    }
    
    formData.append('parallel', document.getElementById('parallel').checked);
    formData.append('incremental', document.getElementById('incremental').checked);

    // 显示加载指示器
    showLoading('正在扫描目录...');

    fetch('/scan/directory', {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error('扫描请求失败');
        }
        return response.json();
    })
    .then(data => {
        hideLoading();
        updateResults(data);
        // 切换到结果标签页
        document.querySelector('a[href="#results"]').click();
    })
    .catch(error => {
        hideLoading();
        console.error('Error:', error);
        alert('扫描失败: ' + error.message);
    });
}

// 更新结果
function updateResults(data) {
    // 更新计数
    document.getElementById('high-count').textContent = data.summary.high;
    document.getElementById('medium-count').textContent = data.summary.medium;
    document.getElementById('low-count').textContent = data.summary.low;

    // 更新图表
    severityChart.data.datasets[0].data = [
        data.summary.high,
        data.summary.medium,
        data.summary.low
    ];
    severityChart.update();

    // 更新漏洞类型图表
    const vulnerabilities = data.summary.vulnerabilities || {};
    const sortedVulns = Object.entries(vulnerabilities)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10);
    
    vulnerabilityChart.data.labels = sortedVulns.map(v => v[0]);
    vulnerabilityChart.data.datasets[0].data = sortedVulns.map(v => v[1]);
    vulnerabilityChart.update();

    // 更新结果列表
    const resultsContainer = document.getElementById('results-container');
    resultsContainer.innerHTML = '';

    if (Object.keys(data.results).length === 0) {
        resultsContainer.innerHTML = `
            <div class="alert alert-success">
                <i class="bi bi-check-circle"></i> 未发现漏洞。
            </div>
        `;
        return;
    }

    for (const [filePath, matches] of Object.entries(data.results)) {
        if (matches.length === 0) continue;

        const fileCard = document.createElement('div');
        fileCard.className = 'card mb-3';
        
        const fileHeader = document.createElement('div');
        fileHeader.className = 'card-header file-item';
        fileHeader.innerHTML = `
            <i class="bi bi-file-earmark-code"></i> ${filePath}
            <span class="badge bg-primary float-end">${matches.length}</span>
        `;
        
        const fileContent = document.createElement('div');
        fileContent.className = 'card-body';
        fileContent.style.display = 'none';
        
        // 添加漏洞列表
        const table = document.createElement('table');
        table.className = 'table table-striped';
        table.innerHTML = `
            <thead>
                <tr>
                    <th>行号</th>
                    <th>严重程度</th>
                    <th>漏洞</th>
                    <th>置信度</th>
                </tr>
            </thead>
            <tbody>
                ${matches.map(match => `
                    <tr>
                        <td>${match.lineNumber}</td>
                        <td>
                            <span class="badge ${getSeverityClass(match.signature.severity)}">
                                ${getSeverityText(match.signature.severity)}
                            </span>
                        </td>
                        <td>
                            <strong>${match.signature.name}</strong>
                            <p>${match.signature.description}</p>
                            <div class="code-block">${escapeHtml(match.matchedCode)}</div>
                        </td>
                        <td>${Math.round(match.confidence * 100)}%</td>
                    </tr>
                `).join('')}
            </tbody>
        `;
        
        fileContent.appendChild(table);
        fileCard.appendChild(fileHeader);
        fileCard.appendChild(fileContent);
        resultsContainer.appendChild(fileCard);
        
        // 添加点击事件
        fileHeader.addEventListener('click', function() {
            if (fileContent.style.display === 'none') {
                fileContent.style.display = 'block';
            } else {
                fileContent.style.display = 'none';
            }
        });
    }
}

// 获取严重程度样式类
function getSeverityClass(severity) {
    switch (severity.toLowerCase()) {
        case 'high': return 'bg-danger';
        case 'medium': return 'bg-warning text-dark';
        case 'low': return 'bg-info text-dark';
        default: return 'bg-secondary';
    }
}

// 获取严重程度文本
function getSeverityText(severity) {
    switch (severity.toLowerCase()) {
        case 'high': return '高危';
        case 'medium': return '中危';
        case 'low': return '低危';
        default: return severity;
    }
}

// HTML转义
function escapeHtml(html) {
    const div = document.createElement('div');
    div.textContent = html;
    return div.innerHTML;
}

// 显示加载指示器
function showLoading(message) {
    let loadingDiv = document.getElementById('loading-indicator');
    if (!loadingDiv) {
        loadingDiv = document.createElement('div');
        loadingDiv.id = 'loading-indicator';
        loadingDiv.className = 'position-fixed top-0 start-0 w-100 h-100 d-flex justify-content-center align-items-center bg-white bg-opacity-75';
        loadingDiv.style.zIndex = '9999';
        loadingDiv.innerHTML = `
            <div class="text-center">
                <div class="spinner-border text-primary" role="status">
                    <span class="visually-hidden">加载中...</span>
                </div>
                <p class="mt-2" id="loading-message">${message || '加载中...'}</p>
            </div>
        `;
        document.body.appendChild(loadingDiv);
    } else {
        document.getElementById('loading-message').textContent = message || '加载中...';
        loadingDiv.style.display = 'flex';
    }
}

// 隐藏加载指示器
function hideLoading() {
    const loadingDiv = document.getElementById('loading-indicator');
    if (loadingDiv) {
        loadingDiv.style.display = 'none';
    }
} 