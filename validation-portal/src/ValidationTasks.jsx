import React, { useState } from 'react';
import { useDropzone } from 'react-dropzone';
import { FiUpload, FiX, FiCheck, FiFile, FiLoader } from 'react-icons/fi';
import axios from 'axios';
import { motion } from 'framer-motion';

const ValidationTasks = () => {
  const [sbomFile, setSbomFile] = useState(null);
  const [excelFile, setExcelFile] = useState(null);
  const [isUploading, setIsUploading] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(0);
  const [validationResult, setValidationResult] = useState(null);
  const [error, setError] = useState(null);
  const [formData, setFormData] = useState({
    workcenter_plantreference: '',
    workcenter_productionareareference: '',
    wokrcenter_usesinglefileassembly: 'No' // Default to 'No'
  });

  const handleDownload = (pdfData, filename = 'Validation_Report.pdf') => {
    const blob = new Blob([pdfData], { type: 'application/pdf' });
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const onDropSbom = (acceptedFiles) => {
    if (acceptedFiles.length) {
      const file = acceptedFiles[0];
      if (file.type === 'text/xml' || file.name.endsWith('.xml')) {
        setSbomFile(file);
        setError(null);
      } else {
        setError('Please upload an XML file for SBOM');
      }
    }
  };

  const onDropExcel = (acceptedFiles) => {
    if (acceptedFiles.length) {
      const file = acceptedFiles[0];
      if (
        file.type.includes('excel') ||
        file.type.includes('spreadsheet') ||
        file.name.endsWith('.xlsx')
      ) {
        setExcelFile(file);
        setError(null);
      } else {
        setError('Please upload an Excel file (.xlsx) for data preparation');
      }
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setFormData({
      ...formData,
      [name]: type === 'checkbox' ? (checked ? 'Yes' : 'No') : value
    });
  };

  const { getRootProps: getSbomRootProps, getInputProps: getSbomInputProps } = useDropzone({
    onDrop: onDropSbom,
    accept: { 'text/xml': ['.xml'] },
    maxFiles: 1
  });

  const { getRootProps: getExcelRootProps, getInputProps: getExcelInputProps } = useDropzone({
    onDrop: onDropExcel,
    accept: { 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet': ['.xlsx'] },
    maxFiles: 1
  });

  const removeSbomFile = () => setSbomFile(null);
  const removeExcelFile = () => setExcelFile(null);

  const handleSubmit = async () => {
    if (!sbomFile || !excelFile) {
      setError('Please upload both files before submitting');
      return;
    }

    const data = new FormData();
    data.append('sbom', sbomFile);
    data.append('excel_file', excelFile);
    data.append('workcenter_plantreference', formData.workcenter_plantreference);
    data.append('workcenter_productionareareference', formData.workcenter_productionareareference);
    data.append('wokrcenter_usesinglefileassembly', formData.wokrcenter_usesinglefileassembly);

    try {
      setIsUploading(true);
      setUploadProgress(0);

      const token = localStorage.getItem('token');

      const response = await axios.post('http://127.0.0.1:8000/api/validate/', data, {
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'multipart/form-data'
        },
        responseType: 'blob',
        onUploadProgress: (progressEvent) => {
          const progress = Math.round((progressEvent.loaded * 100) / progressEvent.total);
          setUploadProgress(progress);
        }
      });

      const filename = response.headers['content-disposition']
        ? response.headers['content-disposition'].split('filename=')[1]
        : 'Validation_Report.pdf';

      setValidationResult({
        message: 'Validation completed successfully!',
        pdfData: response.data,
        filename: filename.replace(/"/g, '')
      });
      setError(null);

      handleDownload(response.data, filename);

    } catch (err) {
      if (err.response?.headers['content-type']?.includes('application/json')) {
        const errorData = JSON.parse(await err.response.data.text());
        setError(errorData.error || 'An error occurred during validation');
      } else {
        setError(err.message || 'An error occurred during validation');
      }
    } finally {
      setIsUploading(false);
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50/70 to-indigo-100/70 rounded-lg py-12 px-4 sm:px-6 lg:px-8">
      <div className="max-w-3xl mx-auto">
        <div className="text-center mb-10">
          <h1 className="text-3xl font-extrabold text-gray-900 sm:text-4xl">
            Validation Portal
          </h1>
          <p className="mt-3 text-xl text-gray-600">
            Upload your SBOM and data files for validation
          </p>
        </div>

        {error && (
          <div className="mb-6 p-4 bg-red-100 border-l-4 border-red-500 text-red-700">
            <p>{error}</p>
          </div>
        )}

        <div className="space-y-8">
          {/* SBOM Upload */}
          <div className="bg-white p-6 rounded-xl shadow-md">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">SBOM File (XML)</h2>
            {!sbomFile ? (
              <div {...getSbomRootProps()} className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-pointer hover:border-blue-400 transition-colors">
                <input {...getSbomInputProps()} />
                <FiUpload className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-2 text-gray-600">Drag & drop your SBOM XML file here</p>
                <p className="mt-1 text-sm text-gray-500">or click to select</p>
              </div>
            ) : (
              <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
                <div className="flex items-center">
                  <FiFile className="h-6 w-6 text-blue-500" />
                  <span className="ml-3 font-medium text-gray-700">{sbomFile.name}</span>
                </div>
                <button onClick={removeSbomFile} className="p-1 rounded-full hover:bg-gray-200 transition-colors">
                  <FiX className="h-5 w-5 text-gray-500" />
                </button>
              </div>
            )}
          </div>

          {/* Excel Upload */}
          <div className="bg-white p-6 rounded-xl shadow-md">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">Data Preparation File (Excel)</h2>
            {!excelFile ? (
              <div {...getExcelRootProps()} className="border-2 border-dashed border-gray-300 rounded-lg p-8 text-center cursor-pointer hover:border-blue-400 transition-colors">
                <input {...getExcelInputProps()} />
                <FiUpload className="mx-auto h-12 w-12 text-gray-400" />
                <p className="mt-2 text-gray-600">Drag & drop your Excel file here</p>
                <p className="mt-1 text-sm text-gray-500">or click to select</p>
              </div>
            ) : (
              <div className="flex items-center justify-between p-4 bg-blue-50 rounded-lg">
                <div className="flex items-center">
                  <FiFile className="h-6 w-6 text-blue-500" />
                  <span className="ml-3 font-medium text-gray-700">{excelFile.name}</span>
                </div>
                <button onClick={removeExcelFile} className="p-1 rounded-full hover:bg-gray-200 transition-colors">
                  <FiX className="h-5 w-5 text-gray-500" />
                </button>
              </div>
            )}
          </div>

          {/* Additional Form Fields */}
          <div className="bg-white p-6 rounded-xl shadow-md">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">Validation Parameters</h2>
            <div className="space-y-4">
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Workcenter Plant Reference
                </label>
                <input
                  type="text"
                  name="workcenter_plantreference"
                  value={formData.workcenter_plantreference}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-700 mb-1">
                  Workcenter Production Area Reference
                </label>
                <input
                  type="text"
                  name="workcenter_productionareareference"
                  value={formData.workcenter_productionareareference}
                  onChange={handleInputChange}
                  className="w-full px-3 py-2 border rounded focus:outline-none focus:ring-2 focus:ring-blue-500"
                />
              </div>
              <div className="flex items-center">
                <input
                  type="checkbox"
                  name="wokrcenter_usesinglefileassembly"
                  checked={formData.wokrcenter_usesinglefileassembly === 'Yes'}
                  onChange={handleInputChange}
                  className="h-4 w-4 text-blue-600 focus:ring-blue-500 border-gray-300 rounded"
                />
                <label className="ml-2 block text-sm text-gray-700">
                  Workcenter Uses Single File Assembly
                </label>
                <span className="ml-2 text-sm text-gray-500">
                  ({formData.wokrcenter_usesinglefileassembly})
                </span>
              </div>
            </div>
          </div>

          {/* Submit Button */}
          <button
            onClick={handleSubmit}
            disabled={isUploading || !sbomFile || !excelFile}
            className={`w-full py-3 px-4 rounded-lg font-medium text-white shadow-md transition-all ${
              isUploading || !sbomFile || !excelFile ? 'bg-blue-300 cursor-not-allowed' : 'bg-blue-600 hover:bg-blue-700'
            }`}
          >
            {isUploading ? (
              <div className="flex items-center justify-center">
                <FiLoader className="animate-spin mr-2" />
                <span>Uploading ({uploadProgress}%)</span>
              </div>
            ) : (
              'Validate Files'
            )}
          </button>
        </div>

        {/* Validation Results */}
        {validationResult && (
          <div className="mt-8 bg-white p-6 rounded-xl shadow-md">
            <h2 className="text-xl font-semibold text-gray-800 mb-4">Validation Results</h2>
            <div className="space-y-4">
              <div className="flex items-center">
                <div className="p-2 rounded-full bg-green-100 text-green-600">
                  <FiCheck className="h-5 w-5" />
                </div>
                <span className="ml-3 font-medium">{validationResult.message}</span>
              </div>

              {validationResult.file && (
                <div className="bg-gray-50 p-4 rounded-lg">
                  <div className="flex items-center justify-between p-3 bg-white rounded-lg shadow-sm">
                    <div className="flex items-center">
                      <FiFile className="h-5 w-5 text-blue-500" />
                      <span className="ml-3 text-gray-700 text-sm truncate">
                        {validationResult.file.name}
                      </span>
                    </div>
                    <button
                      onClick={() => handleDownload(validationResult.pdfData, validationResult.filename)}
                      className="px-3 py-1 bg-indigo-600 text-white rounded hover:bg-indigo-700 transition"
                    >
                      Download
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default ValidationTasks;