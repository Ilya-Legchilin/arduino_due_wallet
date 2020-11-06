#include "Bitcoin.h"
#include "Hash.h"
#include <Conversion.h>
#include <DueFlashStorage.h>
#include <rtc_clock.h>


// Select the Slowclock source
RTC_clock rtc_clock(RC);


#define MAXIMUM_SIZE 1000       //max size of storage
#define MASTER_KEY_LENGTH 112   //length of master key

DueFlashStorage dueFlashStorage;

uint32_t memory_pointer = 0;  //value that shows where is the last record in storage
bool storage_is_full = false; //if this variable is false you can make operations, if true - you can not
uint16_t long_numer = 0;      //256 - digital number to generate private master key "010011101010..."

//Struct of time
struct Time{
  uint8_t seconds;
  uint8_t minutes;
  uint8_t hours;
  uint16_t year;
  uint8_t month;
  uint8_t day;
};


// The struct of the event log.
struct Record{
  Time time;
  char user[16];
  char operation[16];
  char status[16];
};


void print_record(Record record);                   
void print_storage();                               //print the whole storage
void write_record(Record record, uint32_t address); //write the only record in storage
void print_master_key();                            //get master private key from storage and put it into screen
void write_master_key(char * key);                  //write master private key into flash memory
void clean_log();                               //cleaning flash memory, but actually just put 0 or " " everywhere


Time get_time(Time time); //get time from rtc module


/*  Just using basic features of Bitcoin library like: 
 *  generate private master key, derive keys, get signature and hash
 *  if you have to do something important, just look at this code and take features from here
 */
void foo_bar(){

  HDPrivateKey hd("ABCDEFG09"); 
  hd.setSecret((uint8_t*)"");          // put here your 256-digit number, but it should be in string format, not integer!
  Serial.println("Master private key");
  Serial.println(hd);

  HDPublicKey hd_pub = hd.xpub();
  Serial.println("Master public key");
  Serial.println(hd_pub);

  PrivateKey child_private_key0 = hd.child(0);    //that all is just a random using of derivation functions
  Serial.println("Child private key 0");
  Serial.println(child_private_key0);

  
  PublicKey child_public_key0 = child_private_key0.publicKey();
  Serial.println("Child public key 0");
  Serial.println(child_public_key0);

  PrivateKey child_private_key1 = hd.child(1);
  Serial.println("Child private key 1");
  Serial.println(child_private_key1);

  PublicKey child_public_key1 = child_private_key1.publicKey();
  Serial.println("Child public key 1");
  Serial.println(child_public_key1);


  PrivateKey child_private_key2 = hd.child(2);
  Serial.println("Child private key 2");
  Serial.println(child_private_key2);

  PublicKey child_public_key2 = child_private_key2.publicKey();
  Serial.println("Child public key 2");
  Serial.println(child_public_key2);
  Serial.println("-----------------------------------");
  
  String message = "Hello, Roman!";

  byte hash[64] = { 0 }; // hash
  int hashLen = 0;

  // sha512-hmac
  // here we use more c-style approach
  char key[] = "Bitcoin seed";
  hashLen = sha512Hmac((byte*)key, strlen(key), (byte*)message.c_str(), message.length(), hash);
  Serial.println("Sha512-HMAC of \"Hello, Roman!\": " + toHex(hash, hashLen));
  //Serial.println("Should be:   f7fc496a2c17bd09a6328124dc6edebed987e7e93903deee0633a756f1ee81da0753334f6cfe226b5c712d893a68c547d3a5497cd73e1d010670c1e0e9d93a8a");
  
  Signature current_sing = child_private_key2.sign(hash);

  Serial.println("-----------------------------------");
  Serial.println("-----------------Signature for Child private key 2 and hash of message \"Hello, Roman\"-----------------");
  Serial.println(current_sing);
  
  Serial.println("\n");
}


void clean_log(void)
{
  Record idle = {{0, 0, 0, 0, 0, 0}, "", "", ""};
  for (uint32_t i = 0; i < memory_pointer; i++)
      write_record(idle, i);
  Serial.println("Log was cleaned!");
  memory_pointer = 0;
  storage_is_full = false;
}


void setup() {
  Serial.begin(115200);
  
  rtc_clock.init();               //init real time clock to write proper time while recording events
  rtc_clock.set_time(__TIME__);   //__TIME__ and __DATA__ are taken from timestamp when this code was compiled
  rtc_clock.set_date(__DATE__);   //if __DATA__ is 1.1.2007 then this is a problem of compiler

  /*
  for (uint16_t i = 0; i < 256; i++){                       // here you have to get big 256-digital number
    long_numer = long_number + digitalRead(PB21)*(2^i);     // on board with AT91SAM3U input with random signal is 
  }                                                         // on the pin PB21. 
  */
  
}


void write_record(Record record, uint32_t address)
{
  if (memory_pointer < MAXIMUM_SIZE){
    address = address*sizeof(Record);
    byte buffer[sizeof(record)];
    memcpy(buffer, &record, sizeof(record));
    dueFlashStorage.write(address, buffer, sizeof(record));
    memory_pointer++;
    Serial.println("A record was written!");
  }
  else  {
    Serial.println("The storage is full!");
    storage_is_full = true;
  }
}


void print_record(Record record)
{
  Serial.print(" Time: ");
  Serial.print(record.time.hours);
  Serial.print(":");
  Serial.print(record.time.minutes);
  Serial.print(":");
  Serial.print(record.time.seconds);
  Serial.print(" ");
  Serial.print(record.time.day);
  Serial.print(".");
  Serial.print(record.time.month);
  Serial.print(".");
  Serial.print(record.time.year);
  Serial.print(" User: ");
  Serial.print(record.user);
  Serial.print(" Operation: ");
  Serial.print(record.operation);
  Serial.print(" Status: ");
  Serial.print(record.status);
  Serial.println();
}


void print_storage()
{
  if (memory_pointer == 0)
   Serial.println("Storage is empty!");
  else {
    Serial.println("--------------------Begin storage--------------------");
    for (uint32_t j = 0; j < memory_pointer; j++){
      uint16_t i;
      i = j*sizeof(Record);
      byte * b = dueFlashStorage.readAddress(i);
      Record temp_record;
      memcpy(&temp_record, b, sizeof(Record));
      print_record(temp_record);
    }
    Serial.println("--------------------End storage----------------------");
  }
}


Time get_time(Time time)
{
  time.seconds = rtc_clock.get_seconds();
  time.minutes = rtc_clock.get_minutes();
  time.hours = rtc_clock.get_hours();
  time.day = rtc_clock.get_days();
  time.month = rtc_clock.get_months();
  time.year = rtc_clock.get_years();
  return time;
}


void write_master_key(char * key)
{
  uint16_t pointer = (MAXIMUM_SIZE + 1)*sizeof(Record);
  dueFlashStorage.write(pointer, (byte *)key, MASTER_KEY_LENGTH); 
  Serial.println("Master key has been written!");
}


void print_master_key()
{
  uint16_t pointer = (MAXIMUM_SIZE + 1)*sizeof(Record);
  byte * b = dueFlashStorage.readAddress(pointer);
  char temp[MASTER_KEY_LENGTH];
  memcpy(&temp, b, MASTER_KEY_LENGTH);
  Serial.println("This is the master key:");
  Serial.println(temp);
}


void loop() {
  delay(5000);
  foo_bar();
}
