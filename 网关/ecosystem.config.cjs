// pm2 启动配置。用法: pm2 start ecosystem.config.cjs
// 单实例 fork 模式：网关自己管理多端口监听 + 内存限流，不能用 cluster 多实例
// （多实例会抢同一批端口、且限流桶各自独立导致阈值翻倍）。
module.exports = {
  apps: [
    {
      name: 'sub-gateway',
      script: './src/index.js',
      cwd: __dirname, // 以本文件所在目录为工作目录，config.yaml 相对路径才正确
      instances: 1,
      exec_mode: 'fork',
      env: {
        NODE_ENV: 'production',
        SUB_GATEWAY_CONFIG: './config.yaml',
      },
      max_memory_restart: '300M',
      time: true, // 给 pm2 日志加时间戳
    },
  ],
};
