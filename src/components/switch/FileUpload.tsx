'use client';

import React, { useRef, useState } from 'react';
import { UploadCloud, File, Trash2, Plus, AlertCircle } from 'lucide-react';
import { Button } from '@/components/ui/Button';

export interface FileUploadProps {
  files?: File[];
  onFilesChange?: (files: File[]) => void;
  disabled?: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ 
  files = [], 
  onFilesChange,
  disabled = false
}) => {
  const [fileList, setFileList] = useState<File[]>(files);
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Maximum 25MB per file for frontend upload safety
  const MAX_FILE_SIZE = 25 * 1024 * 1024;

  const handleFilesAdded = (incomingFiles: FileList | null) => {
    if (!incomingFiles || incomingFiles.length === 0) return;
    setError(null);

    const validNewFiles: File[] = [];

    for (let i = 0; i < incomingFiles.length; i++) {
      const file = incomingFiles[i];

      if (file.size > MAX_FILE_SIZE) {
        setError(`"${file.name}" exceeds the 25MB limit.`);
        continue;
      }

      // Check for duplicate names in the current selection
      const exists = fileList.some((f) => f.name === file.name && f.size === file.size);
      if (!exists) {
        validNewFiles.push(file);
      }
    }

    if (validNewFiles.length > 0) {
      const updated = [...fileList, ...validNewFiles];
      setFileList(updated);
      if (onFilesChange) onFilesChange(updated);
    }
  };

  const handleDrop = (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDragging(false);
    if (disabled) return;
    handleFilesAdded(e.dataTransfer.files);
  };

  const handleRemove = (index: number) => {
    if (disabled) return;
    const updated = fileList.filter((_, i) => i !== index);
    setFileList(updated);
    if (onFilesChange) onFilesChange(updated);
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes < 1024) return `${bytes} B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  };

  return (
    <div className="space-y-3">
      {/* Hidden native file input */}
      <input
        ref={fileInputRef}
        type="file"
        multiple
        className="hidden"
        disabled={disabled}
        onChange={(e) => {
          handleFilesAdded(e.target.files);
          // reset input value so re-selecting the same file works
          e.target.value = '';
        }}
      />

      <div
        onDragOver={(e) => { 
          e.preventDefault(); 
          if (!disabled) setIsDragging(true); 
        }}
        onDragLeave={() => setIsDragging(false)}
        onDrop={handleDrop}
        className={`border border-dashed rounded-lg p-5 text-center transition-colors ${
          disabled 
            ? 'border-zinc-800 bg-zinc-950/20 opacity-60 cursor-not-allowed'
            : isDragging 
            ? 'border-emerald-500 bg-emerald-950/20' 
            : 'border-zinc-800 hover:border-zinc-700 bg-zinc-950/40'
        }`}
      >
        <UploadCloud className="w-5 h-5 text-zinc-400 mx-auto mb-2" />
        <p className="text-xs font-medium text-zinc-300">
          Drag and drop confidential payload files here
        </p>
        <p className="text-[11px] text-zinc-500 mt-0.5">
          Files are stored privately in encrypted vault storage and released only if switch triggers. (Max 25MB)
        </p>

        <div className="mt-3">
          <Button 
            type="button" 
            variant="outline" 
            size="sm"
            disabled={disabled}
            onClick={() => fileInputRef.current?.click()}
            leftIcon={<Plus className="w-3.5 h-3.5" />}
          >
            Select Real Files
          </Button>
        </div>
      </div>

      {error && (
        <div className="p-2.5 rounded bg-red-950/60 border border-red-800/60 text-red-400 text-xs flex items-center gap-2">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      {fileList.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs font-medium text-zinc-400">
            Selected Files Ready for Upload ({fileList.length})
          </p>
          <div className="space-y-1.5">
            {fileList.map((file, idx) => (
              <div 
                key={`${file.name}-${idx}`}
                className="flex items-center justify-between p-2.5 rounded bg-zinc-900 border border-zinc-800 text-xs"
              >
                <div className="flex items-center gap-2.5 min-w-0">
                  <File className="w-4 h-4 text-emerald-400 shrink-0" />
                  <div className="min-w-0">
                    <p className="font-medium text-zinc-200 truncate">{file.name}</p>
                    <p className="text-[10px] text-zinc-500 font-mono">{formatFileSize(file.size)}</p>
                  </div>
                </div>

                {!disabled && (
                  <button
                    type="button"
                    onClick={() => handleRemove(idx)}
                    className="p-1 text-zinc-500 hover:text-red-400 rounded transition-colors shrink-0 ml-2"
                    title="Remove file"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
};
