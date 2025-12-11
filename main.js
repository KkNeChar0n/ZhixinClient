const { app, BrowserWindow, ipcMain, session } = require('electron');
const path = require('path');
const crypto = require('crypto');
const os = require('os');
const { autoUpdater } = require('electron-updater');
// 使用模拟的keytar模块，避免安装原生模块的问题
const keytar = require('./src/mock-keytar');

// 常量定义
const SERVICE_NAME = 'zhixin-client';
const ACCOUNT_KEY = 'auth-token';
const USERNAME_KEY = 'remembered-username';

// 保持对窗口对象的全局引用，避免被垃圾回收
let loginWindow = null;
let mainWindow = null;

// 应用配置
const isDev = process.env.NODE_ENV === 'development';
const isMac = process.platform === 'darwin';

// 获取本机机器码
function getMachineCode() {
  try {
    // 收集系统信息
    const info = {
      hostname: os.hostname(),
      platform: os.platform(),
      arch: os.arch(),
      cpus: os.cpus().map(cpu => cpu.model),
      totalMem: os.totalmem(),
      networkInterfaces: []
    };

    // 获取MAC地址（排除内部和虚拟接口）
    const interfaces = os.networkInterfaces();
    for (const name in interfaces) {
      for (const iface of interfaces[name]) {
        if (!iface.internal && iface.mac && iface.mac !== '00:00:00:00:00:00') {
          info.networkInterfaces.push({
            name: name,
            mac: iface.mac,
            family: iface.family
          });
        }
      }
    }

    // 将信息转换为字符串并生成哈希
    const infoString = JSON.stringify(info, (key, value) => {
      // 对函数和undefined进行过滤
      if (typeof value === 'function' || value === undefined) {
        return null;
      }
      return value;
    });

    // 使用SHA-256生成哈希，取前16位作为机器码
    const hash = crypto.createHash('sha256').update(infoString).digest('hex');
    return hash.substring(0, 16).toUpperCase(); // 取前16位，大写
  } catch (error) {
    console.error('获取机器码失败:', error);
    // 如果失败，返回一个基于主机名和时间的随机码
    return 'MC_' + crypto.createHash('sha256').update(os.hostname() + Date.now()).digest('hex').substring(0, 13).toUpperCase();
  }
}

// 创建登录窗口
function createLoginWindow() {
  loginWindow = new BrowserWindow({
    width: 400,
    height: 500,
    minWidth: 400,
    minHeight: 500,
    maxWidth: 400,
    maxHeight: 500,
    center: true,
    resizable: false,
    maximizable: false,
    fullscreenable: false,
    show: false,
    frame: false,
    titleBarStyle: 'hiddenInset',
    webPreferences: {
      preload: path.join(__dirname, 'src', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  // 加载登录页面
  loginWindow.loadFile(path.join(__dirname, 'src', 'login.html'));

  // 当窗口准备就绪时显示
  loginWindow.once('ready-to-show', () => {
    loginWindow.show();
    // 开发模式下打开开发者工具
    if (isDev) {
      loginWindow.webContents.openDevTools({ mode: 'detach' });
    }
  });

  // 窗口关闭时清理引用
  loginWindow.on('closed', () => {
    loginWindow = null;
  });
}

// 创建主窗口
function createMainWindow() {
  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    show: false,
    frame: true,
    titleBarStyle: 'default',
    webPreferences: {
      preload: path.join(__dirname, 'src', 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  });

  // 加载主页面
  mainWindow.loadFile(path.join(__dirname, 'src', 'main.html'));

  // 当窗口准备就绪时显示
  mainWindow.once('ready-to-show', () => {
    mainWindow.show();
    // 开发模式下打开开发者工具
    if (isDev) {
      mainWindow.webContents.openDevTools({ mode: 'detach' });
    }
  });

  // 窗口关闭时清理引用
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// 当Electron完成初始化并准备创建窗口时调用
app.whenReady().then(async () => {
  // 设置安全策略
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    callback({
      responseHeaders: {
        ...details.responseHeaders,
        'Content-Security-Policy': ["default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; font-src 'self' data:; img-src 'self' data:;"]
      }
    });
  });

  // 检查是否有有效的登录凭证
  const hasValidToken = await checkAuthToken();
  
  if (hasValidToken) {
    // 有有效凭证，直接创建主窗口
    createMainWindow();
  } else {
    // 无有效凭证，创建登录窗口
    createLoginWindow();
  }

  // macOS应用在没有窗口时重新创建窗口
  app.on('activate', async () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      if (await checkAuthToken()) {
        createMainWindow();
      } else {
        createLoginWindow();
      }
    }
  });
});

// 所有窗口关闭时退出应用（除macOS外）
app.on('window-all-closed', () => {
  if (!isMac) {
    app.quit();
  }
});

// 检查认证token的辅助函数
async function checkAuthToken() {
  try {
    const token = await keytar.getPassword(SERVICE_NAME, ACCOUNT_KEY);
    // 这里可以添加token有效性检查（例如，检查过期时间）
    return !!token;
  } catch (error) {
    console.error('Check auth token failed:', error);
    return false;
  }
}

// IPC处理器：登录
ipcMain.handle('login', async (event, username, password, remember) => {
  try {
    console.log('Attempting login with username:', username);
    
    // 1. 前端密码哈希（SHA-256）
    const passwordHash = crypto.createHash('sha256').update(password).digest('hex');
    
    // 2. 构建请求数据
    const requestData = {
      username: username.trim(),
      password: passwordHash // 注意：实际中后端可能要求不同的哈希方式，这里仅示例
    };
    
    // 3. 模拟HTTPS POST请求到后端API
    // 注意：实际开发中应使用node-fetch或axios等库，并确保使用HTTPS
    console.log('Sending login request with hashed password');
    
    // 模拟网络延迟（1-2秒）
    await new Promise(resolve => setTimeout(resolve, 1000 + Math.random() * 1000));
    
    // 4. 模拟后端响应
    // 这里我们模拟一个成功的登录，实际中应根据后端返回的结果处理
    // 假设后端返回一个JWT token
    const mockToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwidXNlcm5hbWUiOiJ0ZXN0dXNlciIsImlhdCI6MTUxNjIzOTAyMn0.5mhBHqs5_DTLdINd9ni5g-4n_ti2DwX80vU6J8LLzBQ';
    
    // 5. 存储token到安全存储
    await keytar.setPassword(SERVICE_NAME, ACCOUNT_KEY, mockToken);
    
    // 6. 如果用户选择记住账号，存储用户名（不存储密码）
    if (remember) {
      await keytar.setPassword(SERVICE_NAME, USERNAME_KEY, username);
    } else {
      // 否则删除存储的用户名
      await keytar.deletePassword(SERVICE_NAME, USERNAME_KEY);
    }
    
    // 7. 登录成功，关闭登录窗口并打开主窗口（如果主窗口不存在）
    if (loginWindow) {
      loginWindow.close();
      loginWindow = null;
    }
    
    // 创建主窗口
    createMainWindow();
    
    return { success: true, message: '登录成功' };
  } catch (error) {
    console.error('Login failed:', error);
    // 根据错误类型返回相应的错误信息
    let errorMessage = '登录失败，请重试';
    if (error.code === 'ENOTFOUND' || error.code === 'ECONNREFUSED') {
      errorMessage = '网络连接失败，请检查网络设置';
    } else if (error.message.includes('timeout')) {
      errorMessage = '请求超时，请重试';
    }
    return { success: false, message: errorMessage };
  }
});

// IPC处理器：登出
ipcMain.on('logout', async () => {
  try {
    // 清除存储的token
    await keytar.deletePassword(SERVICE_NAME, ACCOUNT_KEY);
    // 注意：不清除用户名，因为用户可能希望下次启动时显示
    
    // 关闭主窗口（如果存在）
    if (mainWindow) {
      mainWindow.close();
      mainWindow = null;
    }
    
    // 创建登录窗口
    createLoginWindow();
  } catch (error) {
    console.error('Logout failed:', error);
  }
});

// IPC处理器：检查认证
ipcMain.handle('check-auth', async () => {
  try {
    const token = await keytar.getPassword(SERVICE_NAME, ACCOUNT_KEY);
    // 这里可以添加token有效性检查（例如，检查过期时间）
    return { isAuthenticated: !!token, token };
  } catch (error) {
    console.error('Check auth failed:', error);
    return { isAuthenticated: false };
  }
});

// IPC处理器：获取存储的用户名
ipcMain.handle('get-stored-username', async () => {
  try {
    const username = await keytar.getPassword(SERVICE_NAME, USERNAME_KEY);
    return username || '';
  } catch (error) {
    console.error('Get stored username failed:', error);
    return '';
  }
});

// IPC处理器：获取本机机器码
ipcMain.handle('get-machine-code', async () => {
  try {
    const machineCode = getMachineCode();
    return { success: true, machineCode: machineCode };
  } catch (error) {
    console.error('Get machine code failed:', error);
    return { success: false, message: '获取机器码失败' };
  }
});

// IPC处理器：获取认证token
ipcMain.handle('get-auth-token', async () => {
  try {
    const token = await keytar.getPassword(SERVICE_NAME, ACCOUNT_KEY);
    return token || '';
  } catch (error) {
    console.error('Get auth token failed:', error);
    return '';
  }
});

// IPC处理器：清除认证token
ipcMain.on('clear-auth-token', async () => {
  try {
    await keytar.deletePassword(SERVICE_NAME, ACCOUNT_KEY);
  } catch (error) {
    console.error('Clear auth token failed:', error);
  }
});

// IPC处理器：窗口控制（通过事件发送）
ipcMain.on('window-control', (event, action) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  if (!win) return;
  
  switch (action) {
    case 'minimize':
      win.minimize();
      break;
    case 'maximize':
      if (win.isMaximized()) {
        win.unmaximize();
      } else {
        win.maximize();
      }
      break;
    case 'close':
      win.close();
      break;
  }
});

// 存储认证token（保留函数，可能在其他地方使用）
async function storeAuthToken(token) {
  try {
    await keytar.setPassword(SERVICE_NAME, ACCOUNT_KEY, token);
    console.log('Token stored securely');
  } catch (error) {
    console.error('Failed to store token:', error);
  }
}

// 清除认证token（保留函数，可能在其他地方使用）
async function clearAuthToken() {
  try {
    await keytar.deletePassword(SERVICE_NAME, ACCOUNT_KEY);
    console.log('Token cleared');
  } catch (error) {
    console.error('Failed to clear token:', error);
  }
}

// 自动更新检查（可选）
if (!isDev) {
  autoUpdater.checkForUpdatesAndNotify();
}