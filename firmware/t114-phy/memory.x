MEMORY
{
  /* The T114 bootloader's S140 v6 layout reserves flash below 0x26000 and
     the first 0x6000 bytes of RAM. */
  FLASH : ORIGIN = 0x00026000, LENGTH = 0x000C6000
  RAM   : ORIGIN = 0x20006000, LENGTH = 232K
}
