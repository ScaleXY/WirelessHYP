#include "transport.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "sdkconfig.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
static char input[512];static size_t used;static bool discard;
static int log_output(const char *fmt,va_list args) {
#ifdef CONFIG_HYP_SILENT_LOGS
    (void)fmt;(void)args;return 0;
#else
    char buf[512];int n=vsnprintf(buf,sizeof(buf),fmt,args);
    if(n>0) uart_write_bytes(UART_NUM_1,buf,(size_t)n<sizeof(buf)?(size_t)n:sizeof(buf)-1);
    return n;
#endif
}
void transport_logs_init(void) {
    /* Console is disabled at build time, including IDF startup logs. */
    esp_log_set_vprintf(log_output);
#ifndef CONFIG_HYP_SILENT_LOGS
    uart_config_t cfg={.baud_rate=115200,.data_bits=UART_DATA_8_BITS,.parity=UART_PARITY_DISABLE,
        .stop_bits=UART_STOP_BITS_1,.flow_ctrl=UART_HW_FLOWCTRL_DISABLE,.source_clk=UART_SCLK_DEFAULT};
    if(uart_param_config(UART_NUM_1,&cfg)==ESP_OK&&
       uart_set_pin(UART_NUM_1,CONFIG_HYP_LOG_TX_PIN,UART_PIN_NO_CHANGE,UART_PIN_NO_CHANGE,UART_PIN_NO_CHANGE)==ESP_OK)
        uart_driver_install(UART_NUM_1,256,2048,0,NULL,0);
#endif
}
int transport_init(void) {
    uart_config_t cfg={.baud_rate=CONFIG_HYP_UART_BAUD,.data_bits=UART_DATA_8_BITS,.parity=UART_PARITY_DISABLE,
        .stop_bits=UART_STOP_BITS_1,.flow_ctrl=UART_HW_FLOWCTRL_DISABLE,.source_clk=UART_SCLK_DEFAULT};
    if(uart_param_config(UART_NUM_0,&cfg)!=ESP_OK) return -1;
    /* DevKitC UART bridge: TX=43, RX=44. Native USB D-/D+ are 19/20. */
    if(uart_set_pin(UART_NUM_0,43,44,UART_PIN_NO_CHANGE,UART_PIN_NO_CHANGE)!=ESP_OK) return -1;
    return uart_driver_install(UART_NUM_0,4096,0,0,NULL,0)==ESP_OK?0:-1;
}
int transport_read_line(char *line,size_t cap) {
    uint8_t b;
    while(uart_read_bytes(UART_NUM_0,&b,1,0)==1) {
        if(b=='\n') {
            int result=discard?-1:1;
            if(used>=cap) result=-1;
            if(result==1) {memcpy(line,input,used);line[used]=0;}
            memset(input,0,sizeof(input));used=0;discard=false;return result;
        }
        if(!b||b>127||used+1>=sizeof(input)) discard=true;
        if(!discard) input[used++]=(char)b;
    }
    return 0;
}
int transport_write_line(const char *line) {
    size_t n=strlen(line);
    if(uart_write_bytes(UART_NUM_0,line,n)!=(int)n) return -1;
    return uart_write_bytes(UART_NUM_0,"\n",1)==1?0:-1;
}
