# Makefile for Packet Sniffer Monitor
# Network Security Tool

CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c11
LDFLAGS = -lpcap
TARGET = packet_sniffer
SRC = packet_sniffer.c

# Colors for output
GREEN = \033[0;32m
YELLOW = \033[0;33m
NC = \033[0m # No Color

.PHONY: all clean install uninstall run help

all: $(TARGET)
	@echo "$(GREEN)Build complete! Run with: sudo ./$(TARGET)$(NC)"

$(TARGET): $(SRC)
	@echo "$(YELLOW)Compiling $(TARGET)...$(NC)"
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC) $(LDFLAGS)
	@echo "$(GREEN)✓ Compilation successful!$(NC)"

clean:
	@echo "$(YELLOW)Cleaning build files...$(NC)"
	rm -f $(TARGET)
	@echo "$(GREEN)✓ Clean complete!$(NC)"

install: $(TARGET)
	@echo "$(YELLOW)Installing $(TARGET) to /usr/local/bin...$(NC)"
	@sudo cp $(TARGET) /usr/local/bin/
	@sudo chmod +x /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✓ Installation complete! Run with: sudo $(TARGET)$(NC)"

uninstall:
	@echo "$(YELLOW)Uninstalling $(TARGET)...$(NC)"
	@sudo rm -f /usr/local/bin/$(TARGET)
	@echo "$(GREEN)✓ Uninstall complete!$(NC)"

run: $(TARGET)
	@echo "$(YELLOW)Running $(TARGET) (requires root)...$(NC)"
	@sudo ./$(TARGET)

help:
	@echo "Packet Sniffer Monitor - Makefile Help"
	@echo ""
	@echo "Available targets:"
	@echo "  make          - Build the packet sniffer"
	@echo "  make clean    - Remove compiled binaries"
	@echo "  make install  - Install to /usr/local/bin (requires sudo)"
	@echo "  make uninstall- Uninstall from /usr/local/bin"
	@echo "  make run      - Compile and run (requires sudo)"
	@echo "  make help     - Show this help message"
	@echo ""
	@echo "Usage examples:"
	@echo "  sudo ./packet_sniffer           # Monitor default interface"
	@echo "  sudo ./packet_sniffer eth0      # Monitor specific interface"
	@echo ""
