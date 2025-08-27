# AskJOE Standardized Logging Utilities
# @author Charles Lomboni (charlesl[at]securityjoes[dot]com)
# @category SecurityJOES
# @runtime PyGhidra

import logging
import os
import datetime

def setup_logging(script_name):
    """
    Setup standardized logging for AskJOE scripts
    
    Args:
        script_name (str): Name of the script for log file naming
        
    Returns:
        tuple: (logger, log_file_path)
    """
    # Create logs directory
    log_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "AskJOE", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    # Create log file name
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    log_file = os.path.join(log_dir, "AskJOE_{}_{}.log".format(script_name, timestamp))
    
    # Get log level from config.ini
    log_level = get_log_level_from_config()
    
    # Configure logger
    logger = logging.getLogger(script_name)
    logger.setLevel(log_level)
    
    # Clear existing handlers to avoid duplicates
    logger.handlers.clear()
    
    # Get logging configuration
    console_logging_enabled = get_logging_config('console_logging', True)
    file_logging_enabled = get_logging_config('file_logging', True)
    
    # Create file handler if enabled
    if file_logging_enabled:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(log_level)
        file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(file_formatter)
        logger.addHandler(file_handler)
    
    # Create console handler if enabled
    if console_logging_enabled:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    return logger, log_file

def get_log_level_from_config():
    """
    Get logging level from config.ini file
    
    Returns:
        int: Logging level constant
    """
    try:
        import configparser
        config_path = os.path.join(os.path.dirname(__file__), "config.ini")
        
        if os.path.exists(config_path):
            config = configparser.ConfigParser()
            config.read(config_path)
            
            # Get log level from config, default to INFO if not found
            log_level_str = config.get('CONFIGURATION', 'log_level', fallback='INFO').upper()
            
            # Convert string to logging level constant
            log_levels = {
                'DEBUG': logging.DEBUG,
                'INFO': logging.INFO,
                'WARNING': logging.WARNING,
                'ERROR': logging.ERROR,
                'CRITICAL': logging.CRITICAL
            }
            
            return log_levels.get(log_level_str, logging.INFO)
        else:
            # Fallback to INFO if config file doesn't exist
            return logging.INFO
            
    except Exception as e:
        # Fallback to INFO if there's any error reading config
        return logging.INFO

def get_logging_config(setting_name, default_value):
    """
    Get logging configuration setting from config.ini file
    
    Args:
        setting_name (str): Name of the setting to retrieve
        default_value: Default value if setting not found
        
    Returns:
        Value from config or default value
    """
    try:
        import configparser
        config_path = os.path.join(os.path.dirname(__file__), "config.ini")
        
        if os.path.exists(config_path):
            config = configparser.ConfigParser()
            config.read(config_path)
            
            # Try to get value from LOGGING section, fallback to default
            if config.has_section('LOGGING'):
                if setting_name == 'console_logging':
                    return config.getboolean('LOGGING', setting_name, fallback=default_value)
                elif setting_name == 'file_logging':
                    return config.getboolean('LOGGING', setting_name, fallback=default_value)
                else:
                    return config.get('LOGGING', setting_name, fallback=default_value)
            else:
                return default_value
        else:
            return default_value
            
    except Exception as e:
        # Fallback to default value if there's any error reading config
        return default_value

def log_info(logger, message):
    """Log info message if logger exists"""
    if logger:
        logger.info(message)

def log_error(logger, message, exc_info=False):
    """Log error message if logger exists"""
    if logger:
        logger.error(message, exc_info=exc_info)

def log_debug(logger, message):
    """Log debug message if logger exists"""
    if logger:
        logger.debug(message)

def log_warning(logger, message):
    """Log warning message if logger exists"""
    if logger:
        logger.warning(message)

def log_critical(logger, message, exc_info=False):
    """Log critical message if logger exists"""
    if logger:
        logger.critical(message, exc_info=exc_info)
