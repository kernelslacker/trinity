#include <glib.h>                               // 包含glib库  
#include <dbus-1.0/dbus/dbus-glib.h>                     // 包含 glib库中D-Bus管理库  
#include <stdio.h> 
#include <glib-2.0/gio/gio.h>

static gboolean send_ding(DBusConnection *bus);// 定义发送消息函数的原型  

int main ()  
{  
   GMainLoop *loop;                             // 定义一个事件循环对象的指针  
   DBusConnection *bus;                         // 定义总线连接对象的指针  
   DBusError error;                             // 定义D-Bus错误消息对象  
   loop = g_main_loop_new(NULL, FALSE);         // 创建新事件循环对象  
   dbus_error_init (&error);                    // 将错误消息对象连接到D-Bus  
                                                // 错误消息对象  
   bus = dbus_bus_get(DBUS_BUS_SESSION, &error);// 连接到总线  
   if (!bus) {                              // 判断是否连接错误  
    g_warning("连接到D-Bus失败: %s", error.message);  
                                        // 使用GLib输出错误警告信息  
      dbus_error_free(&error);              // 清除错误消息  
      return 1;  
   }  
   dbus_connection_setup_with_g_main(bus, NULL);  
                                            // 将总线设为接收GLib事件循环  
   g_timeout_add(1000, (GSourceFunc)send_ding, bus);  
                                    // 每隔1000ms调用一次send_ding()函数  
                                            // 将总线指针作为参数  
   g_main_loop_run(loop);                   // 启动事件循环  
   return 0;  
}  
static gboolean send_ding(DBusConnection *bus)  // 定义发 送消息函数的细节  
{  
   DBusMessage *message;                        // 创建消息对象指针  
   message = dbus_message_new_signal("/com/burtonini/dbus/ding",   
                                       "com.burtonini.dbus.Signal",  
                                       "ding");     // 创建消息对象并标识路径  
   dbus_message_append_args(message,  
                            DBUS_TYPE_STRING, "ding!",  
                            DBUS_TYPE_INVALID);     //将字符串Ding!定义为消息  
   dbus_connection_send(bus, message, NULL);    // 发送该消息  
   dbus_message_unref(message);                 // 释放消息对象  
   g_print("ding!\n");                          // 该函数等同与标准输入输出                                     
   return TRUE;  
}
