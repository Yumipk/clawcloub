# clawcloub-run

感谢佬，🫡在此基础修改重定向
https://github.com/oyz8/ClawCloud-Run

方案一
schedule:
  - cron: '0 7 * * 1'  # 每周一上午7点运行

方案二
schedule:
  # 每周一和周四上午7点运行
  - cron: '0 7 * * 1'  # 周一
  - cron: '0 7 * * 4'  # 周四

