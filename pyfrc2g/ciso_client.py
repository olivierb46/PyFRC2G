"""
CISO Assistant client module for PyFRC2G
Handles uploading generated PDFs to CISO Assistant as evidence revisions
"""

import os
import logging
import traceback
import requests
import urllib3
from requests.exceptions import RequestException, Timeout, ConnectionError, HTTPError

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class CISOCClient:
    """Client for uploading evidence to CISO Assistant"""
    
    def __init__(self, config):
        """
        Initialize CISO Assistant client.
        
        Args:
            config: Config object with CISO Assistant settings
        """
        self.config = config
        self.ciso_url = getattr(config, 'ciso_url', None)
        self.ciso_token = getattr(config, 'ciso_token', None)
        self.ciso_evidence_url = getattr(config, 'ciso_evidence_url', None)
        
        # Check if CISO Assistant is configured
        self.enabled = (
            self.ciso_url and 
            self.ciso_url != "https://<CISO_ASSISTANT_ADDRESS>" and
            self.ciso_token and 
            self.ciso_token != "<CISO_ASSISTANT_TOKEN>" and
            self.ciso_evidence_url and
            self.ciso_evidence_url != f"{self.ciso_url}/api/evidences/<EVIDENCE_ID>/upload/"
        )
        
        if not self.enabled:
            logging.debug("CISO Assistant not configured or disabled")
        else:
            logging.debug(f"CISO Assistant configured: URL={self.ciso_url}, Evidence URL={self.ciso_evidence_url}")
    
    def upload_pdf(self, pdf_path):
        """
        Upload a PDF file to CISO Assistant as an evidence revision.
        
        Args:
            pdf_path: Path to the PDF file to upload
            
        Returns:
            bool: True if upload successful, False otherwise
        """
        if not self.enabled:
            logging.debug("CISO Assistant not enabled, skipping upload")
            return False
        
        if not os.path.exists(pdf_path):
            logging.error(f"PDF file not found: {pdf_path}")
            return False
        
        try:
            # Prepare the file for upload
            pdf_filename = os.path.basename(pdf_path)
            logging.info(f"Uploading {pdf_filename} to CISO Assistant...")
            
            with open(pdf_path, 'rb') as pdf_file:
                files = {
                    'file': (pdf_filename, pdf_file, 'application/pdf')
                }
                
                headers = {
                    'Authorization': f'Token {self.ciso_token}'
                }
                
                # Make the upload request
                response = requests.post(
                    self.ciso_evidence_url,
                    files=files,
                    headers=headers,
                    verify=False,  # CISO Assistant might use self-signed certificates
                    timeout=60  # Large files might take time
                )
                
                # Check response
                response.raise_for_status()
                
                logging.info(f"✓ Successfully uploaded {pdf_filename} to CISO Assistant")
                logging.debug(f"Response: {response.status_code} - {response.text[:200] if response.text else 'No response body'}")
                return True
                
        except Timeout as e:
            logging.error(f"Timeout while uploading {pdf_path} to CISO Assistant: {e}")
            return False
        except ConnectionError as e:
            logging.error(f"Connection error while uploading {pdf_path} to CISO Assistant: {e}")
            logging.error("Check that CISO Assistant is accessible and the URL is correct")
            return False
        except HTTPError as e:
            status_code = e.response.status_code if hasattr(e, 'response') and e.response else 'Unknown'
            if status_code == 401:
                logging.error("Authentication failed. Check your CISO Assistant token.")
            elif status_code == 403:
                logging.error("Access forbidden. Check your CISO Assistant permissions.")
            elif status_code == 404:
                logging.error(f"Evidence endpoint not found. Check the evidence ID in the URL: {self.ciso_evidence_url}")
            else:
                logging.error(f"HTTP error {status_code} while uploading to CISO Assistant: {e}")
            logging.debug(f"Response: {e.response.text[:500] if hasattr(e, 'response') and e.response else 'N/A'}")
            return False
        except RequestException as e:
            logging.error(f"Request error while uploading {pdf_path} to CISO Assistant: {e}")
            return False
        except Exception as e:
            logging.error(f"Unexpected error while uploading {pdf_path} to CISO Assistant: {e}")
            logging.debug(f"Full traceback:\n{traceback.format_exc()}")
            return False
    
    def upload_all_pdfs(self, output_dir):
        """
        Upload all PDF files in the output directory to CISO Assistant.
        
        Args:
            output_dir: Directory containing PDF files to upload
            
        Returns:
            dict: Statistics about uploads (successful, failed, total)
        """
        if not self.enabled:
            logging.debug("CISO Assistant not enabled, skipping uploads")
            return {"successful": 0, "failed": 0, "total": 0}
        
        if not os.path.exists(output_dir):
            logging.warning(f"Output directory not found: {output_dir}")
            return {"successful": 0, "failed": 0, "total": 0}
        
        # Find all PDF files
        pdf_files = []
        for root, dirs, files in os.walk(output_dir):
            for file in files:
                if file.lower().endswith('.pdf'):
                    pdf_files.append(os.path.join(root, file))
        
        if not pdf_files:
            logging.warning(f"No PDF files found in {output_dir}")
            return {"successful": 0, "failed": 0, "total": 0}
        
        logging.info(f"Found {len(pdf_files)} PDF file(s) to upload to CISO Assistant")
        
        stats = {"successful": 0, "failed": 0, "total": len(pdf_files)}
        
        for pdf_path in sorted(pdf_files):
            if self.upload_pdf(pdf_path):
                stats["successful"] += 1
            else:
                stats["failed"] += 1
        
        logging.info(f"CISO Assistant upload complete: {stats['successful']}/{stats['total']} successful")
        
        return stats

